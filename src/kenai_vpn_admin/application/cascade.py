from __future__ import annotations

import hmac
import json
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from kenai_vpn_admin.application.ports import CascadeManager, CascadeRouteSpec, SecretCipher
from kenai_vpn_admin.application.services import DomainConflictError, NotFoundError
from kenai_vpn_admin.domain.enums import LifecycleStatus, NodeRole, OperationalStatus
from kenai_vpn_admin.domain.validation import validate_display_name, validate_slug
from kenai_vpn_admin.infrastructure.models import (
    DeviceAccessTokenModel,
    DeviceModel,
    RouteCredentialModel,
    UserModel,
    VpnLocationModel,
    VpnNodeModel,
    naive_utc,
    utc_now,
)
from kenai_vpn_admin.security import hash_token


@dataclass(frozen=True)
class DeviceActivation:
    user: UserModel
    device: DeviceModel
    access_token: str


@dataclass(frozen=True)
class RouteProfile:
    id: str
    location_id: str
    protocol: str
    client_uri: str


class CascadeService:
    HEALTH_MAX_AGE = timedelta(minutes=2)

    def __init__(self, cipher: SecretCipher, manager: CascadeManager) -> None:
        self.cipher = cipher
        self.manager = manager

    def activate_device(self, db: Session, activation_key: str) -> DeviceActivation | None:
        normalized = activation_key.strip()
        if not normalized or len(normalized) > 128:
            return None
        user = db.scalar(
            select(UserModel)
            .where(
                UserModel.activation_key_hash == hash_token(normalized),
                UserModel.status == LifecycleStatus.ACTIVE.value,
                UserModel.subscription_expires_at > utc_now(),
            )
            .options(selectinload(UserModel.devices))
            .with_for_update()
        )
        if user is None or user.activation_key_consumed_at is not None:
            return None
        device = next((item for item in user.devices if item.slug == "primary"), None)
        if device is None:
            return None
        if device.status != LifecycleStatus.ACTIVE.value:
            return None
        access_token = secrets.token_urlsafe(48)
        db.add(DeviceAccessTokenModel(device_id=device.id, token_hash=hash_token(access_token)))
        user.activation_key_consumed_at = utc_now()
        return DeviceActivation(user, device, access_token)

    @staticmethod
    def resolve_access_token(db: Session, supplied_token: str) -> DeviceAccessTokenModel | None:
        if not supplied_token or len(supplied_token) > 256:
            return None
        token = db.scalar(
            select(DeviceAccessTokenModel)
            .where(
                DeviceAccessTokenModel.token_hash == hash_token(supplied_token),
                DeviceAccessTokenModel.revoked_at.is_(None),
            )
            .options(selectinload(DeviceAccessTokenModel.device).selectinload(DeviceModel.user))
        )
        if token is None:
            return None
        user = token.device.user
        if (
            token.device.status != LifecycleStatus.ACTIVE.value
            or user.status != LifecycleStatus.ACTIVE.value
            or user.subscription_expires_at is None
            or naive_utc(user.subscription_expires_at) <= utc_now()
        ):
            return None
        token.last_used_at = utc_now()
        return token

    @staticmethod
    def list_nodes(db: Session) -> list[VpnNodeModel]:
        return list(db.scalars(select(VpnNodeModel).order_by(VpnNodeModel.role, VpnNodeModel.slug)))

    @staticmethod
    def list_locations(db: Session, *, include_disabled: bool = False) -> list[VpnLocationModel]:
        query = select(VpnLocationModel).options(
            selectinload(VpnLocationModel.ingress_node),
            selectinload(VpnLocationModel.exit_node),
        )
        if not include_disabled:
            query = query.where(VpnLocationModel.status != OperationalStatus.DISABLED.value)
        return list(
            db.scalars(
                query.order_by(
                    VpnLocationModel.sort_order,
                    VpnLocationModel.country_name,
                    VpnLocationModel.city,
                )
            )
        )

    def create_node(
        self,
        db: Session,
        *,
        slug: str,
        display_name: str,
        role: NodeRole,
        country_code: str,
        city: str,
        public_endpoint: str,
        agent_endpoint: str,
        certificate_sha256: str,
    ) -> VpnNodeModel:
        slug = validate_slug(slug)
        if db.scalar(select(VpnNodeModel.id).where(VpnNodeModel.slug == slug)):
            raise DomainConflictError("Node identifier already exists")
        country_code = self._country_code(country_code)
        public_endpoint = self._public_endpoint(public_endpoint)
        agent_endpoint = self._agent_endpoint(agent_endpoint)
        certificate_sha256 = self._certificate_fingerprint(certificate_sha256)
        node = VpnNodeModel(
            slug=slug,
            display_name=validate_display_name(display_name),
            role=role.value,
            country_code=country_code,
            city=validate_display_name(city),
            public_endpoint=public_endpoint,
            agent_endpoint=agent_endpoint or None,
            certificate_sha256=certificate_sha256 or None,
            status=OperationalStatus.OFFLINE.value,
        )
        db.add(node)
        db.flush()
        return node

    def create_location(
        self,
        db: Session,
        *,
        slug: str,
        country_code: str,
        country_name: str,
        city: str,
        display_name: str,
        ingress_node_id: str,
        exit_node_id: str,
        exit_port: int,
        link_uuid: str,
        server_name: str,
        reality_public_key: str,
        short_id: str,
        sort_order: int,
        is_recommended: bool,
    ) -> VpnLocationModel:
        slug = validate_slug(slug)
        if db.scalar(select(VpnLocationModel.id).where(VpnLocationModel.slug == slug)):
            raise DomainConflictError("Location identifier already exists")
        ingress = self._node(db, ingress_node_id)
        exit_node = self._node(db, exit_node_id)
        if ingress.role != NodeRole.INGRESS.value or exit_node.role != NodeRole.EXIT.value:
            raise ValueError("Location requires one ingress node and one exit node")
        if sort_order < 0 or sort_order > 10_000:
            raise ValueError("Location sort order is invalid")
        link = self._exit_link(
            exit_node.public_endpoint,
            exit_port,
            link_uuid,
            server_name,
            reality_public_key,
            short_id,
        )
        location = VpnLocationModel(
            slug=slug,
            country_code=self._country_code(country_code),
            country_name=validate_display_name(country_name),
            city=validate_display_name(city),
            display_name=validate_display_name(display_name),
            ingress_node_id=ingress.id,
            exit_node_id=exit_node.id,
            outbound_tag=f"kenai-exit-{slug}",
            encrypted_exit_link=self.cipher.encrypt(json.dumps(link, sort_keys=True)),
            status=OperationalStatus.OFFLINE.value,
            sort_order=sort_order,
            is_recommended=is_recommended,
        )
        db.add(location)
        db.flush()
        return location

    def cascade_route_specs(self, db: Session) -> list[CascadeRouteSpec]:
        specs: list[CascadeRouteSpec] = []
        for location in self.list_locations(db):
            if location.encrypted_exit_link is None:
                continue
            try:
                link = json.loads(self.cipher.decrypt(location.encrypted_exit_link))
                specs.append(
                    CascadeRouteSpec(
                        location_slug=location.slug,
                        address=str(link["address"]),
                        port=int(link["port"]),
                        client_uuid=str(link["client_uuid"]),
                        server_name=str(link["server_name"]),
                        reality_public_key=str(link["reality_public_key"]),
                        short_id=str(link["short_id"]),
                    )
                )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise DomainConflictError("Stored exit link is invalid") from exc
        return specs

    def refresh_location_health(self, db: Session, location_id: str) -> VpnLocationModel:
        location = self._location(db, location_id)
        if location.status == OperationalStatus.DISABLED.value:
            return location
        checked_at = utc_now()
        result = self.manager.route_health(location.outbound_tag)
        location.last_probe_at = checked_at
        location.latency_ms = result.latency_ms
        location.exit_node.last_seen_at = checked_at
        if result.available:
            location.status = OperationalStatus.ONLINE.value
            location.last_success_at = checked_at
            location.exit_node.status = OperationalStatus.ONLINE.value
            location.exit_node.last_success_at = checked_at
        else:
            location.status = OperationalStatus.OFFLINE.value
            location.exit_node.status = OperationalStatus.OFFLINE.value
        return location

    def profile_for_location(
        self, db: Session, device: DeviceModel, location_id: str
    ) -> RouteProfile:
        location = self._location(db, location_id)
        if not self.location_available(location):
            raise DomainConflictError("Location is unavailable")
        credential = db.scalar(
            select(RouteCredentialModel).where(
                RouteCredentialModel.device_id == device.id,
                RouteCredentialModel.location_id == location.id,
            )
        )
        if credential is not None:
            if credential.status == LifecycleStatus.REVOKED.value:
                raise DomainConflictError("Route profile is revoked")
            if credential.status == LifecycleStatus.DISABLED.value:
                self.manager.set_route_profile_enabled(credential.id, True)
                credential.status = LifecycleStatus.ACTIVE.value
            return self._profile(credential)

        profile_ref = str(uuid.uuid4())
        device_ref = f"{device.user.slug}-{device.slug}"
        issued = self.manager.issue_route_profile(
            profile_ref,
            device_ref,
            location.slug,
            location.outbound_tag,
        )
        credential = RouteCredentialModel(
            id=profile_ref,
            device_id=device.id,
            location_id=location.id,
            client_uuid=issued.public_identifier,
            client_email=issued.client_email,
            encrypted_client_uri=self.cipher.encrypt(issued.client_uri),
            status=LifecycleStatus.ACTIVE.value,
        )
        db.add(credential)
        db.flush()
        return self._profile(credential)

    def expired_route_credentials(self, db: Session) -> list[RouteCredentialModel]:
        return list(
            db.scalars(
                select(RouteCredentialModel)
                .join(RouteCredentialModel.device)
                .join(DeviceModel.user)
                .where(
                    UserModel.activation_key_hash.is_not(None),
                    UserModel.subscription_expires_at <= utc_now(),
                    RouteCredentialModel.status == LifecycleStatus.ACTIVE.value,
                )
            )
        )

    def disable_route_credential(self, credential: RouteCredentialModel) -> None:
        self.manager.set_route_profile_enabled(credential.id, False)
        credential.status = LifecycleStatus.DISABLED.value

    def enable_route_credentials_for_user(self, db: Session, user_id: str) -> None:
        credentials = list(
            db.scalars(
                select(RouteCredentialModel)
                .join(RouteCredentialModel.device)
                .where(
                    DeviceModel.user_id == user_id,
                    RouteCredentialModel.status == LifecycleStatus.DISABLED.value,
                )
            )
        )
        for credential in credentials:
            self.manager.set_route_profile_enabled(credential.id, True)
            credential.status = LifecycleStatus.ACTIVE.value

    def _profile(self, credential: RouteCredentialModel) -> RouteProfile:
        return RouteProfile(
            id=credential.id,
            location_id=credential.location_id,
            protocol="vless-reality",
            client_uri=self.cipher.decrypt(credential.encrypted_client_uri),
        )

    @classmethod
    def location_available(cls, location: VpnLocationModel) -> bool:
        if location.status not in {
            OperationalStatus.ONLINE.value,
            OperationalStatus.DEGRADED.value,
        }:
            return False
        return bool(
            location.last_probe_at
            and naive_utc(location.last_probe_at) >= utc_now() - cls.HEALTH_MAX_AGE
        )

    @staticmethod
    def _node(db: Session, node_id: str) -> VpnNodeModel:
        node = db.get(VpnNodeModel, node_id)
        if node is None:
            raise NotFoundError("VPN node not found")
        return node

    @staticmethod
    def _location(db: Session, location_id: str) -> VpnLocationModel:
        location = db.scalar(
            select(VpnLocationModel)
            .where(VpnLocationModel.id == location_id)
            .options(
                selectinload(VpnLocationModel.ingress_node),
                selectinload(VpnLocationModel.exit_node),
            )
        )
        if location is None:
            raise NotFoundError("VPN location not found")
        return location

    @staticmethod
    def _country_code(value: str) -> str:
        normalized = value.strip().upper()
        if len(normalized) != 2 or not normalized.isascii() or not normalized.isalpha():
            raise ValueError("Country code must contain two Latin letters")
        return normalized

    @staticmethod
    def _public_endpoint(value: str) -> str:
        normalized = value.strip()
        if not normalized or len(normalized) > 253 or any(char.isspace() for char in normalized):
            raise ValueError("Public endpoint is invalid")
        if "://" in normalized or any(char in normalized for char in "/?#"):
            raise ValueError("Public endpoint must be a hostname or IP address")
        return normalized

    @staticmethod
    def _agent_endpoint(value: str) -> str:
        normalized = value.strip()
        if not normalized:
            return ""
        parsed = urlsplit(normalized)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Agent endpoint must be an HTTPS URL without credentials")
        return normalized.rstrip("/")

    @staticmethod
    def _certificate_fingerprint(value: str) -> str:
        normalized = value.strip().lower().replace(":", "")
        if not normalized:
            return ""
        if len(normalized) != 64 or any(char not in "0123456789abcdef" for char in normalized):
            raise ValueError("Certificate fingerprint must be SHA-256")
        return normalized

    @classmethod
    def _exit_link(
        cls,
        address: str,
        port: int,
        client_uuid: str,
        server_name: str,
        reality_public_key: str,
        short_id: str,
    ) -> dict[str, object]:
        if not 1 <= port <= 65535:
            raise ValueError("Exit port is invalid")
        try:
            normalized_uuid = str(uuid.UUID(client_uuid.strip()))
        except ValueError as exc:
            raise ValueError("Inter-server VLESS UUID is invalid") from exc
        normalized_server_name = cls._public_endpoint(server_name)
        normalized_public_key = reality_public_key.strip()
        if not 20 <= len(normalized_public_key) <= 128 or any(
            char.isspace() for char in normalized_public_key
        ):
            raise ValueError("REALITY public key is invalid")
        normalized_short_id = short_id.strip().lower()
        if not 2 <= len(normalized_short_id) <= 16 or len(normalized_short_id) % 2:
            raise ValueError("REALITY short ID is invalid")
        if any(char not in "0123456789abcdef" for char in normalized_short_id):
            raise ValueError("REALITY short ID is invalid")
        return {
            "address": address,
            "port": port,
            "client_uuid": normalized_uuid,
            "server_name": normalized_server_name,
            "reality_public_key": normalized_public_key,
            "short_id": normalized_short_id,
        }


def bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, separator, value = authorization.partition(" ")
    if not separator or not hmac.compare_digest(scheme.casefold(), "bearer"):
        return None
    token = value.strip()
    return token or None


def subscription_timestamp(value: datetime | None) -> str | None:
    return naive_utc(value).isoformat() + "Z" if value is not None else None
