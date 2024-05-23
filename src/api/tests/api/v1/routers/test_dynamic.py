"""Tests for the QualiCharge API dynamic router."""

import json
from random import sample
from typing import cast
from urllib.parse import quote_plus

import pytest
from fastapi import status
from sqlalchemy import func
from sqlalchemy.schema import Column as SAColumn
from sqlmodel import select

from qualicharge.auth.factories import GroupFactory
from qualicharge.auth.schemas import GroupOperationalUnit, ScopesEnum, User
from qualicharge.conf import settings
from qualicharge.factories.dynamic import (
    SessionCreateFactory,
    StatusCreateFactory,
    StatusFactory,
)
from qualicharge.factories.static import (
    PointDeChargeFactory,
    StationFactory,
    StatiqueFactory,
)
from qualicharge.models.dynamic import StatusRead
from qualicharge.schemas.core import (
    OperationalUnit,
    PointDeCharge,
    Session,
    Station,
    Status,
)
from qualicharge.schemas.utils import save_statique, save_statiques


@pytest.mark.parametrize(
    "client_auth",
    (
        (True, {"is_superuser": False, "scopes": []}),
        *[
            (True, {"is_superuser": False, "scopes": [scope]})
            for scope in ScopesEnum
            if scope != ScopesEnum.DYNAMIC_READ
        ],
    ),
    indirect=True,
)
def test_list_statuses_with_missing_scopes(client_auth):
    """Test the /status/ get endpoint scopes."""
    response = client_auth.get("/dynamique/status/")
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_list_statuses_for_superuser(db_session, client_auth):
    """Test the /status/ get endpoint (superuser case)."""
    StatusFactory.__session__ = db_session

    # No status exists
    response = client_auth.get("/dynamique/status/")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == []

    # Create points of charge and statuses
    n_pdc = 2
    n_status_by_pdc = 10
    list(save_statiques(db_session, StatiqueFactory.batch(n_pdc)))
    pdcs = db_session.exec(select(PointDeCharge)).all()
    assert len(pdcs) == n_pdc

    StatusFactory.create_batch_sync(n_status_by_pdc, point_de_charge_id=pdcs[0].id)
    StatusFactory.create_batch_sync(n_status_by_pdc, point_de_charge_id=pdcs[1].id)
    assert db_session.exec(select(func.count(Status.id))).one() == (
        n_pdc * n_status_by_pdc
    )

    # List latest statuses by pdc
    response = client_auth.get("/dynamique/status/")
    assert response.status_code == status.HTTP_200_OK
    statuses = [StatusRead(**s) for s in response.json()]
    assert len(statuses) == n_pdc

    # Check status
    for response_status in statuses:
        pdc = db_session.exec(
            select(PointDeCharge).where(
                PointDeCharge.id_pdc_itinerance == response_status.id_pdc_itinerance
            )
        ).one()
        db_status = db_session.exec(
            select(Status)
            .where(Status.point_de_charge_id == pdc.id)
            .order_by(cast(SAColumn, Status.horodatage).desc())
        ).first()
        assert db_status.etat_pdc == response_status.etat_pdc
        assert db_status.occupation_pdc == response_status.occupation_pdc
        assert db_status.horodatage == response_status.horodatage.astimezone()
        assert db_status.etat_prise_type_2 == response_status.etat_prise_type_2
        assert (
            db_status.etat_prise_type_combo_ccs
            == response_status.etat_prise_type_combo_ccs
        )
        assert (
            db_status.etat_prise_type_chademo == response_status.etat_prise_type_chademo
        )
        assert db_status.etat_prise_type_ef == response_status.etat_prise_type_ef


@pytest.mark.parametrize(
    "client_auth",
    (
        (
            True,
            {
                "is_superuser": False,
                "scopes": [ScopesEnum.DYNAMIC_READ, ScopesEnum.STATIC_CREATE],
            },
        ),
    ),
    indirect=True,
)
def test_list_statuses_for_user_with_no_operational_units(db_session, client_auth):
    """Test the /status/ get endpoint ()."""
    StatusFactory.__session__ = db_session

    # Create points of charge and statuses
    n_pdc = 2
    n_status_by_pdc = 10
    list(save_statiques(db_session, StatiqueFactory.batch(n_pdc)))
    pdcs = db_session.exec(select(PointDeCharge)).all()

    StatusFactory.create_batch_sync(n_status_by_pdc, point_de_charge_id=pdcs[0].id)
    StatusFactory.create_batch_sync(n_status_by_pdc, point_de_charge_id=pdcs[1].id)

    # List latest statuses by pdc
    response = client_auth.get("/dynamique/status/")
    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()) == 0


@pytest.mark.parametrize(
    "client_auth",
    (
        (
            True,
            {
                "is_superuser": False,
                "scopes": [ScopesEnum.DYNAMIC_READ, ScopesEnum.STATIC_CREATE],
            },
        ),
    ),
    indirect=True,
)
def test_list_statuses_for_user(db_session, client_auth):
    """Test the /status/ get endpoint."""
    StatusFactory.__session__ = db_session
    GroupFactory.__session__ = db_session

    # Get user requesting the server
    user = db_session.exec(select(User).where(User.email == "john@doe.com")).one()

    # Create points of charge and statuses
    n_pdc = 10
    n_status_by_pdc = 10
    list(save_statiques(db_session, StatiqueFactory.batch(n_pdc)))
    pdcs = db_session.exec(select(PointDeCharge)).all()
    stations = db_session.exec(select(Station)).all()
    assert len(pdcs) == n_pdc
    assert len(stations) == n_pdc

    for pdc in pdcs:
        StatusFactory.create_batch_sync(n_status_by_pdc, point_de_charge_id=pdc.id)
    assert db_session.exec(select(func.count(Status.id))).one() == (
        n_pdc * n_status_by_pdc
    )

    # Create a group that our user will be attached to
    n_selected_stations = 2
    stations = sample(stations, n_selected_stations)
    operational_units = [station.operational_unit for station in stations]
    GroupFactory.create_sync(operational_units=operational_units, users=[user])

    # Expected PDC
    selected_pdcs = db_session.exec(
        select(PointDeCharge)
        .join_from(PointDeCharge, Station, PointDeCharge.station_id == Station.id)
        .where(
            cast(SAColumn, PointDeCharge.station_id).in_(
                station.id for station in stations
            )
        )
        .order_by(PointDeCharge.id_pdc_itinerance)
    ).all()

    # List latest statuses by pdc
    response = client_auth.get("/dynamique/status/")
    assert response.status_code == status.HTTP_200_OK
    statuses = [StatusRead(**s) for s in response.json()]
    assert len(statuses) == len(selected_pdcs)


def test_list_statuses_filters(db_session, client_auth):  # noqa: PLR0915
    """Test the /status/ get endpoint filters."""
    StationFactory.__session__ = db_session
    PointDeChargeFactory.__session__ = db_session
    StatusFactory.__session__ = db_session

    # Create stations, points of charge and statuses
    n_station = 2
    n_pdc_by_station = 2
    n_status_by_pdc = 2
    stations = StationFactory.create_batch_sync(n_station)
    for station in stations:
        PointDeChargeFactory.create_batch_sync(n_pdc_by_station, station_id=station.id)
    pdcs = db_session.exec(select(PointDeCharge)).all()
    assert len(pdcs) == n_station * n_pdc_by_station
    for pdc in pdcs:
        StatusFactory.create_batch_sync(n_status_by_pdc, point_de_charge_id=pdc.id)
    assert db_session.exec(select(func.count(Status.id))).one() == (
        n_station * n_pdc_by_station * n_status_by_pdc
    )

    # List all latest statuses by pdc
    response = client_auth.get("/dynamique/status/")
    assert response.status_code == status.HTTP_200_OK
    statuses = [StatusRead(**s) for s in response.json()]
    assert len(statuses) == n_station * n_pdc_by_station

    # Filter with invalid PDC
    response = client_auth.get("/dynamique/status/?pdc=foo")
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    # Filter with one pdc
    response = client_auth.get(f"/dynamique/status/?pdc={pdcs[0].id_pdc_itinerance}")
    assert response.status_code == status.HTTP_200_OK
    statuses = [StatusRead(**s) for s in response.json()]
    assert len(statuses) == 1

    # Filter with two pdcs
    selected_pdc_indexes = (0, 1)
    query = "&".join(
        f"pdc={pdcs[idx].id_pdc_itinerance}" for idx in selected_pdc_indexes
    )
    response = client_auth.get(f"/dynamique/status/?{query}")
    assert response.status_code == status.HTTP_200_OK
    statuses = [StatusRead(**s) for s in response.json()]
    assert len(statuses) == len(selected_pdc_indexes)

    # Filter with invalid station
    response = client_auth.get("/dynamique/status/?station=foo")
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    # Filter with one station
    response = client_auth.get(
        f"/dynamique/status/?station={stations[0].id_station_itinerance}"
    )
    assert response.status_code == status.HTTP_200_OK
    statuses = [StatusRead(**s) for s in response.json()]
    assert len(statuses) == n_pdc_by_station
    assert {s.id_pdc_itinerance for s in statuses} == {
        p.id_pdc_itinerance for p in stations[0].points_de_charge
    }

    # Filter with two stations
    query = "&".join(f"station={station.id_station_itinerance}" for station in stations)
    response = client_auth.get(f"/dynamique/status/?{query}")
    assert response.status_code == status.HTTP_200_OK
    statuses = [StatusRead(**s) for s in response.json()]
    assert len(statuses) == n_station * n_pdc_by_station

    # Filter with one station and one pdc from another station
    query = (
        f"station={stations[0].id_station_itinerance}&"
        f"pdc={stations[1].points_de_charge[0].id_pdc_itinerance}"
    )
    response = client_auth.get(f"/dynamique/status/?{query}")
    assert response.status_code == status.HTTP_200_OK
    statuses = [StatusRead(**s) for s in response.json()]
    # 2 for the station and 1 for the pdc (from a different station)
    expected_statuses = 3
    assert len(statuses) == expected_statuses

    # Filter with one station and one pdc from the same station
    query = (
        f"station={stations[0].id_station_itinerance}&"
        f"pdc={stations[0].points_de_charge[0].id_pdc_itinerance}"
    )
    response = client_auth.get(f"/dynamique/status/?{query}")
    assert response.status_code == status.HTTP_200_OK
    statuses = [StatusRead(**s) for s in response.json()]
    # 2 for the station (as the extra pdc is from the same station)
    expected_statuses = 2
    assert len(statuses) == expected_statuses
    assert {s.id_pdc_itinerance for s in statuses} == {
        p.id_pdc_itinerance for p in stations[0].points_de_charge
    }

    # Filter with invalid from date time
    response = client_auth.get("/dynamique/status/?from=foo")
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    # Filter with only latest status datetime
    statuses = db_session.exec(select(Status).order_by(Status.horodatage)).all()
    from_ = quote_plus(statuses[-1].horodatage.isoformat())
    response = client_auth.get(f"/dynamique/status/?from={from_}")
    assert response.status_code == status.HTTP_200_OK
    statuses = [StatusRead(**s) for s in response.json()]
    assert len(statuses) == 1

    # Filter with only latest status datetime and pdc
    response = client_auth.get(
        f"/dynamique/status/?from={from_}&pdc={statuses[-1].id_pdc_itinerance}"
    )
    assert response.status_code == status.HTTP_200_OK
    statuses = [StatusRead(**s) for s in response.json()]
    assert len(statuses) == 1

    # Filter with the oldest status datetime
    statuses = db_session.exec(select(Status).order_by(Status.horodatage)).all()
    from_ = quote_plus(statuses[0].horodatage.isoformat())
    response = client_auth.get(f"/dynamique/status/?from={from_}")
    assert response.status_code == status.HTTP_200_OK
    statuses = [StatusRead(**s) for s in response.json()]
    assert len(statuses) == n_station * n_pdc_by_station


def test_read_status_for_non_existing_point_of_charge(client_auth):
    """Test the /status/{id_pdc_itinerance} endpoint for unknown point of charge."""
    response = client_auth.get("/dynamique/status/FR911E1111ER1")
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": "Selected point of charge does not exist"}


def test_read_status_for_non_existing_status(db_session, client_auth):
    """Test the /status/{id_pdc_itinerance} endpoint for non existing status."""
    id_pdc_itinerance = "FR911E1111ER1"
    save_statique(
        db_session, StatiqueFactory.build(id_pdc_itinerance=id_pdc_itinerance)
    )

    response = client_auth.get(f"/dynamique/status/{id_pdc_itinerance}")
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {
        "detail": "Selected point of charge does not have status record yet"
    }


@pytest.mark.parametrize(
    "client_auth",
    (
        (True, {"is_superuser": False, "scopes": []}),
        *[
            (True, {"is_superuser": False, "scopes": [scope]})
            for scope in ScopesEnum
            if scope != ScopesEnum.DYNAMIC_READ
        ],
    ),
    indirect=True,
)
def test_read_status_with_missing_scopes(client_auth):
    """Test the /status/{id_pdc_itinerance} endpoint scopes."""
    # Create the PointDeCharge
    id_pdc_itinerance = "FR911E1111ER1"
    # Get latest status
    response = client_auth.get(f"/dynamique/status/{id_pdc_itinerance}")
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_read_status_for_superuser(db_session, client_auth):
    """Test the /status/{id_pdc_itinerance} endpoint (superuser case)."""
    StatusFactory.__session__ = db_session

    # Create the PointDeCharge
    id_pdc_itinerance = "FR911E1111ER1"
    save_statique(
        db_session, StatiqueFactory.build(id_pdc_itinerance=id_pdc_itinerance)
    )
    pdc = db_session.exec(
        select(PointDeCharge).where(
            PointDeCharge.id_pdc_itinerance == id_pdc_itinerance
        )
    ).one()

    # Create 20 attached statuses
    n_statuses = 20
    StatusFactory.create_batch_sync(n_statuses, point_de_charge_id=pdc.id)
    assert (
        db_session.exec(
            select(func.count(Status.id)).where(Status.point_de_charge_id == pdc.id)
        ).one()
        == n_statuses
    )
    # Expected status
    expected_status = db_session.exec(
        select(Status)
        .where(Status.point_de_charge_id == pdc.id)
        .order_by(cast(SAColumn, Status.horodatage).desc())
        .limit(1)
    ).one()

    # Get latest status
    response = client_auth.get(f"/dynamique/status/{id_pdc_itinerance}")
    assert response.status_code == status.HTTP_200_OK
    response_status = StatusRead(**response.json())
    assert expected_status.etat_pdc == response_status.etat_pdc
    assert expected_status.occupation_pdc == response_status.occupation_pdc
    assert expected_status.horodatage == response_status.horodatage.astimezone()
    assert expected_status.etat_prise_type_2 == response_status.etat_prise_type_2
    assert (
        expected_status.etat_prise_type_combo_ccs
        == response_status.etat_prise_type_combo_ccs
    )
    assert (
        expected_status.etat_prise_type_chademo
        == response_status.etat_prise_type_chademo
    )
    assert expected_status.etat_prise_type_ef == response_status.etat_prise_type_ef


@pytest.mark.parametrize(
    "client_auth",
    (
        (
            True,
            {
                "is_superuser": False,
                "scopes": [ScopesEnum.DYNAMIC_READ, ScopesEnum.STATIC_CREATE],
            },
        ),
    ),
    indirect=True,
)
def test_read_status_for_user(db_session, client_auth):
    """Test the /status/{id_pdc_itinerance} endpoint."""
    StatusFactory.__session__ = db_session

    # Create the PointDeCharge
    id_pdc_itinerance = "FR911E1111ER1"
    save_statique(
        db_session, StatiqueFactory.build(id_pdc_itinerance=id_pdc_itinerance)
    )
    pdc = db_session.exec(
        select(PointDeCharge).where(
            PointDeCharge.id_pdc_itinerance == id_pdc_itinerance
        )
    ).one()

    # Create 20 attached statuses
    n_statuses = 20
    StatusFactory.create_batch_sync(n_statuses, point_de_charge_id=pdc.id)
    assert (
        db_session.exec(
            select(func.count(Status.id)).where(Status.point_de_charge_id == pdc.id)
        ).one()
        == n_statuses
    )

    # User has no assigned operational units
    response = client_auth.get(f"/dynamique/status/{id_pdc_itinerance}")
    assert response.status_code == status.HTTP_403_FORBIDDEN

    # Expected status
    expected_status = db_session.exec(
        select(Status)
        .where(Status.point_de_charge_id == pdc.id)
        .order_by(cast(SAColumn, Status.horodatage).desc())
        .limit(1)
    ).one()

    # Get user requesting the server
    user = db_session.exec(select(User).where(User.email == "john@doe.com")).one()
    # link him to an operational unit
    operational_unit = db_session.exec(
        select(OperationalUnit).where(OperationalUnit.code == "FR911")
    ).one()
    GroupFactory.create_sync(users=[user], operational_units=[operational_unit])

    # Get latest status
    response = client_auth.get(f"/dynamique/status/{id_pdc_itinerance}")
    assert response.status_code == status.HTTP_200_OK
    response_status = StatusRead(**response.json())
    assert expected_status.horodatage == response_status.horodatage.astimezone()


def test_read_status_history_for_non_existing_point_of_charge(client_auth):
    """Test the /status/{id_pdc_itinerance}/history endpoint for unknown PDC."""
    response = client_auth.get("/dynamique/status/FR911E1111ER1/history")
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": "Selected point of charge does not exist"}


def test_read_status_history_for_non_existing_status(db_session, client_auth):
    """Test the /status/{id_pdc_itinerance}/history endpoint for non existing status."""
    id_pdc_itinerance = "FR911E1111ER1"
    save_statique(
        db_session, StatiqueFactory.build(id_pdc_itinerance=id_pdc_itinerance)
    )

    response = client_auth.get(f"/dynamique/status/{id_pdc_itinerance}/history")
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {
        "detail": "Selected point of charge does not have status record yet"
    }


@pytest.mark.parametrize(
    "client_auth",
    (
        (True, {"is_superuser": False, "scopes": []}),
        *[
            (True, {"is_superuser": False, "scopes": [scope]})
            for scope in ScopesEnum
            if scope != ScopesEnum.DYNAMIC_READ
        ],
    ),
    indirect=True,
)
def test_read_status_history_with_missing_scopes(client_auth):
    """Test the /status/{id_pdc_itinerance}/history endpoint scopes."""
    id_pdc_itinerance = "FR911E1111ER1"
    response = client_auth.get(f"/dynamique/status/{id_pdc_itinerance}/history")
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_read_status_history_for_superuser(db_session, client_auth):
    """Test the /status/{id_pdc_itinerance}/history endpoint (superuser case)."""
    StatusFactory.__session__ = db_session

    # Create the PointDeCharge
    id_pdc_itinerance = "FR911E1111ER1"
    save_statique(
        db_session, StatiqueFactory.build(id_pdc_itinerance=id_pdc_itinerance)
    )
    pdc = db_session.exec(
        select(PointDeCharge).where(
            PointDeCharge.id_pdc_itinerance == id_pdc_itinerance
        )
    ).one()

    # Create 20 attached statuses
    n_statuses = 20
    StatusFactory.create_batch_sync(n_statuses, point_de_charge_id=pdc.id)
    assert (
        db_session.exec(
            select(func.count(Status.id)).where(Status.point_de_charge_id == pdc.id)
        ).one()
        == n_statuses
    )
    # Expected status
    expected_statuses = db_session.exec(
        select(Status)
        .where(Status.point_de_charge_id == pdc.id)
        .order_by(Status.horodatage)
    ).all()

    # Get latest status
    response = client_auth.get(f"/dynamique/status/{id_pdc_itinerance}/history")
    assert response.status_code == status.HTTP_200_OK
    response_statuses = [StatusRead(**s) for s in response.json()]
    assert len(response_statuses) == len(expected_statuses)

    for expected_status, response_status in zip(expected_statuses, response_statuses):
        assert expected_status.etat_pdc == response_status.etat_pdc
        assert expected_status.occupation_pdc == response_status.occupation_pdc
        assert expected_status.horodatage == response_status.horodatage.astimezone()
        assert expected_status.etat_prise_type_2 == response_status.etat_prise_type_2
        assert (
            expected_status.etat_prise_type_combo_ccs
            == response_status.etat_prise_type_combo_ccs
        )
        assert (
            expected_status.etat_prise_type_chademo
            == response_status.etat_prise_type_chademo
        )
        assert expected_status.etat_prise_type_ef == response_status.etat_prise_type_ef


@pytest.mark.parametrize(
    "client_auth",
    (
        (True, {"is_superuser": False, "scopes": [ScopesEnum.DYNAMIC_READ]}),
        (
            True,
            {
                "is_superuser": False,
                "scopes": [ScopesEnum.DYNAMIC_READ, ScopesEnum.STATIC_CREATE],
            },
        ),
    ),
    indirect=True,
)
def test_read_status_history_for_user(db_session, client_auth):
    """Test the /status/{id_pdc_itinerance}/history endpoint."""
    StatusFactory.__session__ = db_session

    # Create the PointDeCharge
    id_pdc_itinerance = "FR911E1111ER1"
    save_statique(
        db_session, StatiqueFactory.build(id_pdc_itinerance=id_pdc_itinerance)
    )
    pdc = db_session.exec(
        select(PointDeCharge).where(
            PointDeCharge.id_pdc_itinerance == id_pdc_itinerance
        )
    ).one()

    # Create 20 attached statuses
    n_statuses = 20
    StatusFactory.create_batch_sync(n_statuses, point_de_charge_id=pdc.id)
    assert (
        db_session.exec(
            select(func.count(Status.id)).where(Status.point_de_charge_id == pdc.id)
        ).one()
        == n_statuses
    )
    # Expected status
    expected_statuses = db_session.exec(
        select(Status)
        .where(Status.point_de_charge_id == pdc.id)
        .order_by(Status.horodatage)
    ).all()

    # User has no assigned operational units
    response = client_auth.get(f"/dynamique/status/{id_pdc_itinerance}/history")
    assert response.status_code == status.HTTP_403_FORBIDDEN

    # Get user requesting the server
    user = db_session.exec(select(User).where(User.email == "john@doe.com")).one()
    # link him to an operational unit
    operational_unit = db_session.exec(
        select(OperationalUnit).where(OperationalUnit.code == "FR911")
    ).one()
    GroupFactory.create_sync(users=[user], operational_units=[operational_unit])

    # Get latest status
    response = client_auth.get(f"/dynamique/status/{id_pdc_itinerance}/history")
    assert response.status_code == status.HTTP_200_OK
    response_statuses = [StatusRead(**s) for s in response.json()]
    assert len(response_statuses) == len(expected_statuses)

    for expected_status, response_status in zip(expected_statuses, response_statuses):
        assert expected_status.horodatage == response_status.horodatage.astimezone()


def test_read_status_history_filters(db_session, client_auth):
    """Test the /status/{id_pdc_itinerance}/history endpoint filters."""
    StatusFactory.__session__ = db_session

    # Create the PointDeCharge
    id_pdc_itinerance = "FR911E1111ER1"
    save_statique(
        db_session, StatiqueFactory.build(id_pdc_itinerance=id_pdc_itinerance)
    )
    pdc = db_session.exec(
        select(PointDeCharge).where(
            PointDeCharge.id_pdc_itinerance == id_pdc_itinerance
        )
    ).one()

    # Create 20 attached statuses
    n_statuses = 20
    StatusFactory.create_batch_sync(n_statuses, point_de_charge_id=pdc.id)
    assert (
        db_session.exec(
            select(func.count(Status.id)).where(Status.point_de_charge_id == pdc.id)
        ).one()
        == n_statuses
    )
    # All statuses
    db_statuses = db_session.exec(
        select(Status)
        .where(Status.point_de_charge_id == pdc.id)
        .order_by(Status.horodatage)
    ).all()

    # Get latest status
    from_ = quote_plus(db_statuses[-1].horodatage.isoformat())
    response = client_auth.get(
        f"/dynamique/status/{id_pdc_itinerance}/history?from={from_}"
    )
    assert response.status_code == status.HTTP_200_OK
    response_statuses = [StatusRead(**s) for s in response.json()]
    assert len(response_statuses) == 1

    # Filter with the oldest status datetime
    from_ = quote_plus(db_statuses[0].horodatage.isoformat())
    response = client_auth.get(
        f"/dynamique/status/{id_pdc_itinerance}/history?from={from_}"
    )
    assert response.status_code == status.HTTP_200_OK
    statuses = [StatusRead(**s) for s in response.json()]
    assert len(statuses) == n_statuses


def test_create_status_for_non_existing_point_of_charge(client_auth):
    """Test the /status/ create endpoint for non existing point of charge."""
    id_pdc_itinerance = "FR911E1111ER1"
    qc_status = StatusCreateFactory.build(id_pdc_itinerance=id_pdc_itinerance)

    # Point of charge does not exist yet
    response = client_auth.post(
        "/dynamique/status/", json=json.loads(qc_status.model_dump_json())
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": "Attached point of charge does not exist"}


@pytest.mark.parametrize(
    "client_auth",
    (
        (True, {"is_superuser": False, "scopes": []}),
        *[
            (True, {"is_superuser": False, "scopes": [scope]})
            for scope in ScopesEnum
            if scope != ScopesEnum.DYNAMIC_CREATE
        ],
    ),
    indirect=True,
)
def test_create_status_with_missing_scopes(client_auth):
    """Test the /status/ create endpoint scopes."""
    id_pdc_itinerance = "FR911E1111ER1"
    qc_status = StatusCreateFactory.build(id_pdc_itinerance=id_pdc_itinerance)

    # Create a new status
    response = client_auth.post(
        "/dynamique/status/", json=json.loads(qc_status.model_dump_json())
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_create_status_for_superuser(db_session, client_auth):
    """Test the /status/ create endpoint (superuser case)."""
    id_pdc_itinerance = "FR911E1111ER1"
    qc_status = StatusCreateFactory.build(id_pdc_itinerance=id_pdc_itinerance)

    # Create point of charge
    save_statique(
        db_session, StatiqueFactory.build(id_pdc_itinerance=id_pdc_itinerance)
    )

    # Create a new status
    response = client_auth.post(
        "/dynamique/status/", json=json.loads(qc_status.model_dump_json())
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json() is None

    # Query database to check created status and relations
    pdc = db_session.exec(
        select(PointDeCharge).where(
            PointDeCharge.id_pdc_itinerance == qc_status.id_pdc_itinerance
        )
    ).one()
    db_status = db_session.exec(select(Status)).one()
    assert db_status.point_de_charge_id == pdc.id
    assert db_status in pdc.statuses


@pytest.mark.parametrize(
    "client_auth",
    (
        (True, {"is_superuser": False, "scopes": [ScopesEnum.DYNAMIC_CREATE]}),
        (
            True,
            {
                "is_superuser": False,
                "scopes": [ScopesEnum.DYNAMIC_READ, ScopesEnum.DYNAMIC_CREATE],
            },
        ),
    ),
    indirect=True,
)
def test_create_status_for_user(db_session, client_auth):
    """Test the /status/ create endpoint."""
    id_pdc_itinerance = "FR911E1111ER1"
    qc_status = StatusCreateFactory.build(id_pdc_itinerance=id_pdc_itinerance)

    # Create point of charge
    save_statique(
        db_session, StatiqueFactory.build(id_pdc_itinerance=id_pdc_itinerance)
    )

    # User has no assigned operational units
    response = client_auth.post(
        "/dynamique/status/", json=json.loads(qc_status.model_dump_json())
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json() == {
        "message": (
            "Unsufficient permissions: You cannot create statuses for "
            "this point of charge"
        )
    }

    # Get user requesting the server
    user = db_session.exec(select(User).where(User.email == "john@doe.com")).one()
    # link him to an operational unit
    operational_unit = db_session.exec(
        select(OperationalUnit).where(OperationalUnit.code == "FR911")
    ).one()
    GroupFactory.create_sync(users=[user], operational_units=[operational_unit])

    # Create a new status
    response = client_auth.post(
        "/dynamique/status/", json=json.loads(qc_status.model_dump_json())
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json() is None

    # Query database to check created status and relations
    pdc = db_session.exec(
        select(PointDeCharge).where(
            PointDeCharge.id_pdc_itinerance == qc_status.id_pdc_itinerance
        )
    ).one()
    db_status = db_session.exec(select(Status)).one()
    assert db_status.point_de_charge_id == pdc.id
    assert db_status in pdc.statuses


def test_create_status_bulk_for_missing_point_of_charge(db_session, client_auth):
    """Test the /status/bulk create endpoint for missing point of charge."""
    qc_statuses = StatusCreateFactory.batch(3)

    # Points of charge does not exist yet
    response = client_auth.post(
        "/dynamique/status/bulk",
        json=[json.loads(s.model_dump_json()) for s in qc_statuses],
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {
        "detail": (
            "Undeclared attached point(s) of charge, "
            "you should create them all first"
        )
    }

    # Create 2 over 3 points of charge
    save_statiques(
        db_session,
        [
            StatiqueFactory.build(id_pdc_itinerance=qc_statuses[0].id_pdc_itinerance),
            StatiqueFactory.build(id_pdc_itinerance=qc_statuses[1].id_pdc_itinerance),
        ],
    )

    # We expect the same answer as one point of charge does not exist
    response = client_auth.post(
        "/dynamique/status/bulk",
        json=[json.loads(s.model_dump_json()) for s in qc_statuses],
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {
        "detail": (
            "Undeclared attached point(s) of charge, "
            "you should create them all first"
        )
    }


@pytest.mark.parametrize(
    "client_auth",
    (
        (True, {"is_superuser": False, "scopes": []}),
        *[
            (True, {"is_superuser": False, "scopes": [scope]})
            for scope in ScopesEnum
            if scope != ScopesEnum.DYNAMIC_CREATE
        ],
    ),
    indirect=True,
)
def test_create_status_bulk_with_missing_scopes(client_auth):
    """Test the /status/bulk create endpoint."""
    qc_statuses = StatusCreateFactory.batch(3)
    response = client_auth.post(
        "/dynamique/status/bulk",
        json=[json.loads(s.model_dump_json()) for s in qc_statuses],
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_create_status_bulk_for_superuser(db_session, client_auth):
    """Test the /status/bulk create endpoint (superuser case)."""
    qc_statuses = StatusCreateFactory.batch(3)

    # Create points of charge
    list(
        save_statiques(
            db_session,
            [
                StatiqueFactory.build(id_pdc_itinerance=s.id_pdc_itinerance)
                for s in qc_statuses
            ],
        )
    )

    # Assert no status exist
    assert db_session.exec(select(func.count(Status.id))).one() == 0

    # We expect the same answer as one point of charge does not exist
    response = client_auth.post(
        "/dynamique/status/bulk",
        json=[json.loads(s.model_dump_json()) for s in qc_statuses],
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json() is None

    # Check created statuses
    db_statuses = db_session.exec(select(Status)).all()
    db_pdcs = db_session.exec(select(PointDeCharge)).all()
    assert len(db_statuses) == len(qc_statuses)
    assert {s.point_de_charge_id for s in db_statuses} == {p.id for p in db_pdcs}

    # Check foreign keys
    for qc_status in qc_statuses:
        db_pdc = db_session.exec(
            select(PointDeCharge).where(
                PointDeCharge.id_pdc_itinerance == qc_status.id_pdc_itinerance
            )
        ).one()
        db_status = db_session.exec(
            select(Status).where(Status.point_de_charge_id == db_pdc.id)
        ).one()
        assert db_status.etat_pdc == qc_status.etat_pdc
        assert db_status.occupation_pdc == qc_status.occupation_pdc
        assert db_status.horodatage == qc_status.horodatage.astimezone()
        assert db_status.etat_prise_type_2 == qc_status.etat_prise_type_2
        assert (
            db_status.etat_prise_type_combo_ccs == qc_status.etat_prise_type_combo_ccs
        )
        assert db_status.etat_prise_type_chademo == qc_status.etat_prise_type_chademo
        assert db_status.etat_prise_type_ef == qc_status.etat_prise_type_ef


@pytest.mark.parametrize(
    "client_auth",
    (
        (True, {"is_superuser": False, "scopes": [ScopesEnum.DYNAMIC_CREATE]}),
        (
            True,
            {
                "is_superuser": False,
                "scopes": [ScopesEnum.DYNAMIC_READ, ScopesEnum.DYNAMIC_CREATE],
            },
        ),
    ),
    indirect=True,
)
def test_create_status_bulk_for_user(db_session, client_auth):
    """Test the /status/bulk create endpoint."""
    qc_statuses = StatusCreateFactory.batch(3)

    # Create points of charge
    list(
        save_statiques(
            db_session,
            [
                StatiqueFactory.build(id_pdc_itinerance=s.id_pdc_itinerance)
                for s in qc_statuses
            ],
        )
    )

    # Assert no status exist
    assert db_session.exec(select(func.count(Status.id))).one() == 0

    # Get created stations
    stations = db_session.exec(select(Station)).all()
    assert len(stations) == len(qc_statuses)

    # User has no assigned operational units
    response = client_auth.post(
        "/dynamique/status/bulk",
        json=[json.loads(s.model_dump_json()) for s in qc_statuses],
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json() == {
        "message": (
            "Unsufficient permissions: You cannot submit data for an "
            "organization you are not assigned to"
        )
    }

    # Get user requesting the server
    user = db_session.exec(select(User).where(User.email == "john@doe.com")).one()
    # link him to a operational units
    operational_units = db_session.exec(
        select(OperationalUnit).where(
            cast(SAColumn, OperationalUnit.code).in_(
                station.operational_unit.code for station in stations[:2]
            )
        )
    ).all()
    GroupFactory.create_sync(users=[user], operational_units=operational_units)

    # We expect a permission error as one station/operational_unit is not linked to the
    # current user
    response = client_auth.post(
        "/dynamique/status/bulk",
        json=[json.loads(s.model_dump_json()) for s in qc_statuses],
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json() == {
        "message": (
            "Unsufficient permissions: You cannot submit data for an "
            "organization you are not assigned to"
        )
    }

    # Assign user to the missing operational unit
    db_session.add(
        GroupOperationalUnit(
            group_id=user.groups[0].id,
            operational_unit_id=stations[2].operational_unit.id,
        )
    )
    db_session.refresh(user.groups[0])
    response = client_auth.post(
        "/dynamique/status/bulk",
        json=[json.loads(s.model_dump_json()) for s in qc_statuses],
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json() is None

    # Check created statuses
    db_statuses = db_session.exec(select(Status)).all()
    db_pdcs = db_session.exec(select(PointDeCharge)).all()
    assert len(db_statuses) == len(qc_statuses)
    assert {s.point_de_charge_id for s in db_statuses} == {p.id for p in db_pdcs}

    # Check foreign keys
    for qc_status in qc_statuses:
        db_pdc = db_session.exec(
            select(PointDeCharge).where(
                PointDeCharge.id_pdc_itinerance == qc_status.id_pdc_itinerance
            )
        ).one()
        db_status = db_session.exec(
            select(Status).where(Status.point_de_charge_id == db_pdc.id)
        ).one()
        assert db_status.horodatage == qc_status.horodatage.astimezone()


def test_create_status_bulk_with_outbound_sizes(client_auth):
    """Test the /status/bulk create endpoint with a single or too many statuses."""
    # We expert more than one status for this endpoint
    response = client_auth.post(
        "/dynamique/status/bulk",
        json=[json.loads(StatusCreateFactory.build().model_dump_json())],
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    # We expect at most settings.API_STATUS_BULK_CREATE_MAX_SIZE statuses for this
    # endpoint
    response = client_auth.post(
        "/dynamique/status/bulk",
        json=[
            json.loads(s.model_dump_json())
            for s in StatusCreateFactory.batch(
                settings.API_STATUS_BULK_CREATE_MAX_SIZE + 1
            )
        ],
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_create_session_for_non_existing_point_of_charge(client_auth):
    """Test the /session/ create endpoint for non existing point of charge."""
    id_pdc_itinerance = "FR911E1111ER1"
    qc_session = SessionCreateFactory.build(id_pdc_itinerance=id_pdc_itinerance)

    # Point of charge does not exist yet
    response = client_auth.post(
        "/dynamique/session/", json=json.loads(qc_session.model_dump_json())
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": "Attached point of charge does not exist"}


@pytest.mark.parametrize(
    "client_auth",
    (
        (True, {"is_superuser": False, "scopes": []}),
        *[
            (True, {"is_superuser": False, "scopes": [scope]})
            for scope in ScopesEnum
            if scope != ScopesEnum.DYNAMIC_CREATE
        ],
    ),
    indirect=True,
)
def test_create_session_with_missing_scopes(client_auth):
    """Test the /session/ create endpoint scopes."""
    id_pdc_itinerance = "FR911E1111ER1"
    qc_session = SessionCreateFactory.build(id_pdc_itinerance=id_pdc_itinerance)

    response = client_auth.post(
        "/dynamique/session/", json=json.loads(qc_session.model_dump_json())
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_create_session_for_superuser(db_session, client_auth):
    """Test the /session/ create endpoint (superuser case)."""
    id_pdc_itinerance = "FR911E1111ER1"
    qc_session = SessionCreateFactory.build(id_pdc_itinerance=id_pdc_itinerance)

    # Create point of charge
    save_statique(
        db_session, StatiqueFactory.build(id_pdc_itinerance=id_pdc_itinerance)
    )

    # Create a new status
    response = client_auth.post(
        "/dynamique/session/", json=json.loads(qc_session.model_dump_json())
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json() is None

    # Query database to check created status and relations
    pdc = db_session.exec(
        select(PointDeCharge).where(
            PointDeCharge.id_pdc_itinerance == qc_session.id_pdc_itinerance
        )
    ).one()
    db_qc_session = db_session.exec(select(Session)).one()
    assert db_qc_session.point_de_charge_id == pdc.id
    assert db_qc_session in pdc.sessions


@pytest.mark.parametrize(
    "client_auth",
    (
        (True, {"is_superuser": False, "scopes": [ScopesEnum.DYNAMIC_CREATE]}),
        (
            True,
            {
                "is_superuser": False,
                "scopes": [ScopesEnum.DYNAMIC_READ, ScopesEnum.DYNAMIC_CREATE],
            },
        ),
    ),
    indirect=True,
)
def test_create_session_for_user(db_session, client_auth):
    """Test the /session/ create endpoint."""
    id_pdc_itinerance = "FR911E1111ER1"
    qc_session = SessionCreateFactory.build(id_pdc_itinerance=id_pdc_itinerance)

    # Create point of charge
    save_statique(
        db_session, StatiqueFactory.build(id_pdc_itinerance=id_pdc_itinerance)
    )

    # User has no assigned operational units
    response = client_auth.post(
        "/dynamique/session/", json=json.loads(qc_session.model_dump_json())
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json() == {
        "message": (
            "Unsufficient permissions: You cannot create sessions for "
            "this point of charge"
        )
    }

    # Get user requesting the server
    user = db_session.exec(select(User).where(User.email == "john@doe.com")).one()
    # link him to an operational unit
    operational_unit = db_session.exec(
        select(OperationalUnit).where(OperationalUnit.code == "FR911")
    ).one()
    GroupFactory.create_sync(users=[user], operational_units=[operational_unit])

    # Create a new status
    response = client_auth.post(
        "/dynamique/session/", json=json.loads(qc_session.model_dump_json())
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json() is None

    # Query database to check created status and relations
    pdc = db_session.exec(
        select(PointDeCharge).where(
            PointDeCharge.id_pdc_itinerance == qc_session.id_pdc_itinerance
        )
    ).one()
    db_qc_session = db_session.exec(select(Session)).one()
    assert db_qc_session.point_de_charge_id == pdc.id
    assert db_qc_session in pdc.sessions


def test_create_session_bulk_for_missing_point_of_charge(db_session, client_auth):
    """Test the /session/bulk create endpoint for missing point of charge."""
    qc_sessions = SessionCreateFactory.batch(3)

    # Points of charge does not exist yet
    response = client_auth.post(
        "/dynamique/session/bulk",
        json=[json.loads(s.model_dump_json()) for s in qc_sessions],
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {
        "detail": (
            "Undeclared attached point(s) of charge, "
            "you should create them all first"
        )
    }

    # Create 2 over 3 points of charge
    save_statiques(
        db_session,
        [
            StatiqueFactory.build(id_pdc_itinerance=qc_sessions[0].id_pdc_itinerance),
            StatiqueFactory.build(id_pdc_itinerance=qc_sessions[1].id_pdc_itinerance),
        ],
    )

    # We expect the same answer as one point of charge does not exist
    response = client_auth.post(
        "/dynamique/session/bulk",
        json=[json.loads(s.model_dump_json()) for s in qc_sessions],
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {
        "detail": (
            "Undeclared attached point(s) of charge, "
            "you should create them all first"
        )
    }


@pytest.mark.parametrize(
    "client_auth",
    (
        (True, {"is_superuser": False, "scopes": []}),
        *[
            (True, {"is_superuser": False, "scopes": [scope]})
            for scope in ScopesEnum
            if scope != ScopesEnum.DYNAMIC_CREATE
        ],
    ),
    indirect=True,
)
def test_create_session_bulk_with_missing_scopes(client_auth):
    """Test the /session/bulk create endpoint scopes."""
    qc_sessions = SessionCreateFactory.batch(3)

    response = client_auth.post(
        "/dynamique/session/bulk",
        json=[json.loads(s.model_dump_json()) for s in qc_sessions],
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_create_session_bulk_for_superuser(db_session, client_auth):
    """Test the /session/bulk create endpoint."""
    qc_sessions = SessionCreateFactory.batch(3)

    # Create points of charge
    list(
        save_statiques(
            db_session,
            [
                StatiqueFactory.build(id_pdc_itinerance=s.id_pdc_itinerance)
                for s in qc_sessions
            ],
        )
    )

    # Assert no session exist
    assert db_session.exec(select(func.count(Session.id))).one() == 0

    # We expect the same answer as one point of charge does not exist
    response = client_auth.post(
        "/dynamique/session/bulk",
        json=[json.loads(s.model_dump_json()) for s in qc_sessions],
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json() is None

    # Check created statuses
    db_qc_sessions = db_session.exec(select(Session)).all()
    db_pdcs = db_session.exec(select(PointDeCharge)).all()
    assert len(db_qc_sessions) == len(qc_sessions)
    assert {s.point_de_charge_id for s in db_qc_sessions} == {p.id for p in db_pdcs}

    # Check foreign keys
    for qc_session in qc_sessions:
        db_pdc = db_session.exec(
            select(PointDeCharge).where(
                PointDeCharge.id_pdc_itinerance == qc_session.id_pdc_itinerance
            )
        ).one()
        db_qc_session = db_session.exec(
            select(Session).where(Session.point_de_charge_id == db_pdc.id)
        ).one()
        assert db_qc_session.start == qc_session.start.astimezone()
        assert db_qc_session.end == qc_session.end.astimezone()
        assert db_qc_session.energy == qc_session.energy


@pytest.mark.parametrize(
    "client_auth",
    (
        (True, {"is_superuser": False, "scopes": [ScopesEnum.DYNAMIC_CREATE]}),
        (
            True,
            {
                "is_superuser": False,
                "scopes": [ScopesEnum.DYNAMIC_READ, ScopesEnum.DYNAMIC_CREATE],
            },
        ),
    ),
    indirect=True,
)
def test_create_session_bulk_for_user(db_session, client_auth):
    """Test the /session/bulk create endpoint."""
    qc_sessions = SessionCreateFactory.batch(3)

    # Create points of charge
    list(
        save_statiques(
            db_session,
            [
                StatiqueFactory.build(id_pdc_itinerance=s.id_pdc_itinerance)
                for s in qc_sessions
            ],
        )
    )

    # Assert no session exist
    assert db_session.exec(select(func.count(Session.id))).one() == 0

    # Get created stations
    stations = db_session.exec(select(Station)).all()
    assert len(stations) == len(qc_sessions)

    # User has no assigned operational units
    response = client_auth.post(
        "/dynamique/session/bulk",
        json=[json.loads(s.model_dump_json()) for s in qc_sessions],
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json() == {
        "message": (
            "Unsufficient permissions: You cannot submit data for an "
            "organization you are not assigned to"
        )
    }

    # Get user requesting the server
    user = db_session.exec(select(User).where(User.email == "john@doe.com")).one()
    # link him to a operational units
    operational_units = db_session.exec(
        select(OperationalUnit).where(
            cast(SAColumn, OperationalUnit.code).in_(
                station.operational_unit.code for station in stations[:2]
            )
        )
    ).all()
    GroupFactory.create_sync(users=[user], operational_units=operational_units)

    # We expect a permission error as one station/operational_unit is not linked to the
    # current user
    response = client_auth.post(
        "/dynamique/session/bulk",
        json=[json.loads(s.model_dump_json()) for s in qc_sessions],
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json() == {
        "message": (
            "Unsufficient permissions: You cannot submit data for an "
            "organization you are not assigned to"
        )
    }

    # We expect the same answer as one point of charge does not exist
    db_session.add(
        GroupOperationalUnit(
            group_id=user.groups[0].id,
            operational_unit_id=stations[2].operational_unit.id,
        )
    )
    db_session.refresh(user.groups[0])
    response = client_auth.post(
        "/dynamique/session/bulk",
        json=[json.loads(s.model_dump_json()) for s in qc_sessions],
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json() is None

    # Check created statuses
    db_qc_sessions = db_session.exec(select(Session)).all()
    db_pdcs = db_session.exec(select(PointDeCharge)).all()
    assert len(db_qc_sessions) == len(qc_sessions)
    assert {s.point_de_charge_id for s in db_qc_sessions} == {p.id for p in db_pdcs}

    # Check foreign keys
    for qc_session in qc_sessions:
        db_pdc = db_session.exec(
            select(PointDeCharge).where(
                PointDeCharge.id_pdc_itinerance == qc_session.id_pdc_itinerance
            )
        ).one()
        db_qc_session = db_session.exec(
            select(Session).where(Session.point_de_charge_id == db_pdc.id)
        ).one()
        assert db_qc_session.start == qc_session.start.astimezone()
        assert db_qc_session.end == qc_session.end.astimezone()
        assert db_qc_session.energy == qc_session.energy


def test_create_session_bulk_with_outbound_sizes(client_auth):
    """Test the /session/bulk create endpoint with a single or too many statuses."""
    # We expert more than one status for this endpoint
    response = client_auth.post(
        "/dynamique/session/bulk",
        json=[json.loads(SessionCreateFactory.build().model_dump_json())],
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    # We expect at most settings.API_STATUS_BULK_CREATE_MAX_SIZE statuses for this
    # endpoint
    response = client_auth.post(
        "/dynamique/session/bulk",
        json=[
            json.loads(s.model_dump_json())
            for s in SessionCreateFactory.batch(
                settings.API_SESSION_BULK_CREATE_MAX_SIZE + 1
            )
        ],
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
