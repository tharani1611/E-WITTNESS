"""Object storage abstraction and S3-compatible client with SigV4 pre-signing (Phase 45).

Enforces:
- Private evidence storage by default (SEC-011).
- Server-generated opaque object keys.
- Short-lived, scoped pre-signed upload and download URLs via AWS SigV4.
- Zero leakage of raw storage credentials in URLs or API responses.
- In-memory test double for deterministic offline unit testing.
"""

from __future__ import annotations

import hashlib
import hmac
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, runtime_checkable
from urllib.parse import quote, urlencode, urlsplit

import httpx

from backend.app.config.settings import Settings
from backend.app.core.exceptions import (
    BusinessRuleError,
    ResourceNotFoundError,
    ServiceUnavailableError,
)
from backend.app.core.logging import get_logger

logger = get_logger("infrastructure.storage")


@dataclass(frozen=True)
class PresignedUploadData:
    """Details and pre-signed endpoint for direct client-side binary uploads."""

    upload_url: str
    upload_method: str = "PUT"
    headers: dict[str, str] = field(default_factory=dict)
    expires_at: datetime = field(default_factory=lambda: datetime.now(UTC) + timedelta(minutes=15))


@dataclass(frozen=True)
class StorageObjectMetadata:
    """Metadata for an existing object in storage."""

    storage_key: str
    content_length: int
    content_type: str
    etag: str | None = None
    last_modified: datetime | None = None


@runtime_checkable
class ObjectStorageClient(Protocol):
    """Protocol defining the object storage operations required by E-WITNESS."""

    def generate_presigned_upload_url(
        self,
        storage_key: str,
        content_type: str,
        expires_in_seconds: int = 900,
    ) -> PresignedUploadData:
        """Generate a short-lived, pre-signed HTTP PUT URL for uploading an evidence object."""
        ...

    def generate_presigned_download_url(
        self,
        storage_key: str,
        expires_in_seconds: int = 300,
    ) -> str:
        """Generate a short-lived, pre-signed HTTP GET URL for downloading an evidence object."""
        ...

    def generate_presigned_part_upload_url(
        self,
        storage_key: str,
        upload_id: str,
        part_number: int,
        expires_in_seconds: int = 900,
    ) -> str:
        """Generate a pre-signed URL for uploading a specific chunk in a multipart session."""
        ...

    async def initiate_multipart_upload(
        self,
        storage_key: str,
        content_type: str,
    ) -> str:
        """Initialize a multipart upload session and return the provider upload ID."""
        ...

    async def complete_multipart_upload(
        self,
        storage_key: str,
        upload_id: str,
        parts: list[dict[str, Any]],
    ) -> StorageObjectMetadata:
        """Assemble and finalize uploaded parts into a single persistent object."""
        ...

    async def abort_multipart_upload(
        self,
        storage_key: str,
        upload_id: str,
    ) -> bool:
        """Abort a multipart session and release incomplete parts."""
        ...

    async def verify_object_exists(self, storage_key: str) -> bool:
        """Check whether an object exists in storage without retrieving its full payload."""
        ...

    async def get_object_metadata(self, storage_key: str) -> StorageObjectMetadata | None:
        """Retrieve metadata for an existing storage object."""
        ...

    async def get_object_bytes(self, storage_key: str) -> bytes:
        """Retrieve the binary payload of an object for server-side validation and scanning."""
        ...

    async def delete_object(self, storage_key: str) -> bool:
        """Delete an object from storage if permitted by retention policy."""
        ...


class S3StorageClient:
    """Production S3-compatible object storage client using AWS SigV4."""

    def __init__(self, settings: Settings) -> None:
        self._endpoint_url = settings.STORAGE_ENDPOINT_URL.rstrip("/")
        self._bucket_name = settings.STORAGE_BUCKET_NAME
        self._region = settings.STORAGE_REGION
        self._access_key = settings.STORAGE_ACCESS_KEY.get_secret_value()
        self._secret_key = settings.STORAGE_SECRET_KEY.get_secret_value()
        self._use_ssl = settings.STORAGE_USE_SSL
        self._verify_tls = settings.STORAGE_VERIFY_TLS
        self._timeout_seconds = settings.STORAGE_TIMEOUT_SECONDS

        url_parts = urlsplit(self._endpoint_url)
        self._host = url_parts.netloc
        self._scheme = url_parts.scheme

    def _sign(self, key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    def _get_signature_key(self, date_stamp: str) -> bytes:
        k_date = self._sign(f"AWS4{self._secret_key}".encode(), date_stamp)
        k_region = hmac.new(k_date, self._region.encode("utf-8"), hashlib.sha256).digest()
        k_service = hmac.new(k_region, b"s3", hashlib.sha256).digest()
        return hmac.new(k_service, b"aws4_request", hashlib.sha256).digest()

    def generate_presigned_upload_url(
        self,
        storage_key: str,
        content_type: str,
        expires_in_seconds: int = 900,
    ) -> PresignedUploadData:
        """Generate SigV4 pre-signed PUT URL for uploading evidence."""
        now = datetime.now(UTC)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")
        expires_at = now + timedelta(seconds=expires_in_seconds)

        clean_key = storage_key.lstrip("/")
        canonical_uri = f"/{self._bucket_name}/{quote(clean_key)}"

        credential_scope = f"{date_stamp}/{self._region}/s3/aws4_request"
        canonical_querystring = urlencode(
            [
                ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
                ("X-Amz-Credential", f"{self._access_key}/{credential_scope}"),
                ("X-Amz-Date", amz_date),
                ("X-Amz-Expires", str(expires_in_seconds)),
                ("X-Amz-SignedHeaders", "host"),
            ]
        )

        canonical_headers = f"host:{self._host}\n"
        signed_headers = "host"
        payload_hash = "UNSIGNED-PAYLOAD"

        canonical_request = (
            f"PUT\n{canonical_uri}\n{canonical_querystring}\n"
            f"{canonical_headers}\n{signed_headers}\n{payload_hash}"
        )

        string_to_sign = (
            f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n"
            f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
        )

        signing_key = self._get_signature_key(date_stamp)
        signature = hmac.new(
            signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        final_url = f"{self._endpoint_url}{canonical_uri}?{canonical_querystring}&X-Amz-Signature={signature}"

        return PresignedUploadData(
            upload_url=final_url,
            upload_method="PUT",
            headers={"Content-Type": content_type},
            expires_at=expires_at,
        )

    def generate_presigned_download_url(
        self,
        storage_key: str,
        expires_in_seconds: int = 300,
    ) -> str:
        """Generate SigV4 pre-signed GET URL for downloading evidence."""
        now = datetime.now(UTC)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")

        clean_key = storage_key.lstrip("/")
        canonical_uri = f"/{self._bucket_name}/{quote(clean_key)}"

        credential_scope = f"{date_stamp}/{self._region}/s3/aws4_request"
        canonical_querystring = urlencode(
            [
                ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
                ("X-Amz-Credential", f"{self._access_key}/{credential_scope}"),
                ("X-Amz-Date", amz_date),
                ("X-Amz-Expires", str(expires_in_seconds)),
                ("X-Amz-SignedHeaders", "host"),
            ]
        )

        canonical_headers = f"host:{self._host}\n"
        signed_headers = "host"
        payload_hash = "UNSIGNED-PAYLOAD"

        canonical_request = (
            f"GET\n{canonical_uri}\n{canonical_querystring}\n"
            f"{canonical_headers}\n{signed_headers}\n{payload_hash}"
        )

        string_to_sign = (
            f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n"
            f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
        )

        signing_key = self._get_signature_key(date_stamp)
        signature = hmac.new(
            signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        return f"{self._endpoint_url}{canonical_uri}?{canonical_querystring}&X-Amz-Signature={signature}"

    async def verify_object_exists(self, storage_key: str) -> bool:
        """Send authenticated HEAD request to verify object presence."""
        download_url = self.generate_presigned_download_url(storage_key, expires_in_seconds=60)
        try:
            async with httpx.AsyncClient(
                verify=self._verify_tls,
                timeout=self._timeout_seconds,
            ) as client:
                resp = await client.head(download_url)
                if resp.status_code == 200:
                    return True
                if resp.status_code == 404:
                    return False
                logger.warning(
                    "Unexpected storage provider HEAD response",
                    extra={"status_code": resp.status_code, "storage_key": storage_key},
                )
                return False
        except httpx.RequestError as exc:
            logger.error("Storage connection failure during verify_object_exists", exc_info=exc)
            raise ServiceUnavailableError(
                "Object storage service is temporarily unavailable."
            ) from None

    async def get_object_metadata(self, storage_key: str) -> StorageObjectMetadata | None:
        """Retrieve metadata for an existing object via authenticated HEAD request."""
        download_url = self.generate_presigned_download_url(storage_key, expires_in_seconds=60)
        try:
            async with httpx.AsyncClient(
                verify=self._verify_tls,
                timeout=self._timeout_seconds,
            ) as client:
                resp = await client.head(download_url)
                if resp.status_code == 404:
                    return None
                if resp.status_code != 200:
                    raise ServiceUnavailableError("Failed to query object storage.")

                length = int(resp.headers.get("Content-Length", 0))
                ctype = resp.headers.get("Content-Type", "application/octet-stream")
                etag = resp.headers.get("ETag")
                return StorageObjectMetadata(
                    storage_key=storage_key,
                    content_length=length,
                    content_type=ctype,
                    etag=etag.strip('"') if etag else None,
                )
        except httpx.RequestError as exc:
            logger.error("Storage connection failure during get_object_metadata", exc_info=exc)
            raise ServiceUnavailableError(
                "Object storage service is temporarily unavailable."
            ) from None

    async def delete_object(self, storage_key: str) -> bool:
        """Delete an object from storage."""
        # Evidence objects are immutable; deletion only allowed for unconfirmed/cancelled sessions
        clean_key = storage_key.lstrip("/")
        now = datetime.now(UTC)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")

        canonical_uri = f"/{self._bucket_name}/{quote(clean_key)}"
        credential_scope = f"{date_stamp}/{self._region}/s3/aws4_request"
        canonical_querystring = urlencode(
            [
                ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
                ("X-Amz-Credential", f"{self._access_key}/{credential_scope}"),
                ("X-Amz-Date", amz_date),
                ("X-Amz-Expires", "60"),
                ("X-Amz-SignedHeaders", "host"),
            ]
        )

        canonical_headers = f"host:{self._host}\n"
        signed_headers = "host"
        payload_hash = "UNSIGNED-PAYLOAD"

        canonical_request = (
            f"DELETE\n{canonical_uri}\n{canonical_querystring}\n"
            f"{canonical_headers}\n{signed_headers}\n{payload_hash}"
        )

        string_to_sign = (
            f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n"
            f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
        )

        signing_key = self._get_signature_key(date_stamp)
        signature = hmac.new(
            signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        delete_url = f"{self._endpoint_url}{canonical_uri}?{canonical_querystring}&X-Amz-Signature={signature}"

        try:
            async with httpx.AsyncClient(
                verify=self._verify_tls,
                timeout=self._timeout_seconds,
            ) as client:
                resp = await client.delete(delete_url)
                return resp.status_code in {200, 204}
        except httpx.RequestError as exc:
            logger.error("Storage delete request failed", exc_info=exc)
            raise ServiceUnavailableError(
                "Object storage service is temporarily unavailable."
            ) from None

    def generate_presigned_part_upload_url(
        self,
        storage_key: str,
        upload_id: str,
        part_number: int,
        expires_in_seconds: int = 900,
    ) -> str:
        """Generate SigV4 pre-signed PUT URL for uploading a specific part in a multipart session."""
        now = datetime.now(UTC)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")

        clean_key = storage_key.lstrip("/")
        canonical_uri = f"/{self._bucket_name}/{quote(clean_key)}"

        credential_scope = f"{date_stamp}/{self._region}/s3/aws4_request"
        params = [
            ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
            ("X-Amz-Credential", f"{self._access_key}/{credential_scope}"),
            ("X-Amz-Date", amz_date),
            ("X-Amz-Expires", str(expires_in_seconds)),
            ("X-Amz-SignedHeaders", "host"),
            ("partNumber", str(part_number)),
            ("uploadId", upload_id),
        ]
        params.sort(key=lambda x: x[0])
        canonical_querystring = urlencode(params)

        canonical_headers = f"host:{self._host}\n"
        signed_headers = "host"
        payload_hash = "UNSIGNED-PAYLOAD"

        canonical_request = (
            f"PUT\n{canonical_uri}\n{canonical_querystring}\n"
            f"{canonical_headers}\n{signed_headers}\n{payload_hash}"
        )

        string_to_sign = (
            f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n"
            f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
        )

        signing_key = self._get_signature_key(date_stamp)
        signature = hmac.new(
            signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        return f"{self._endpoint_url}{canonical_uri}?{canonical_querystring}&X-Amz-Signature={signature}"

    async def initiate_multipart_upload(
        self,
        storage_key: str,
        content_type: str,
    ) -> str:
        """Initiate S3 multipart upload and return the UploadId."""
        clean_key = storage_key.lstrip("/")
        now = datetime.now(UTC)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")

        canonical_uri = f"/{self._bucket_name}/{quote(clean_key)}"
        credential_scope = f"{date_stamp}/{self._region}/s3/aws4_request"
        params = [
            ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
            ("X-Amz-Credential", f"{self._access_key}/{credential_scope}"),
            ("X-Amz-Date", amz_date),
            ("X-Amz-Expires", "60"),
            ("X-Amz-SignedHeaders", "host"),
            ("uploads", ""),
        ]
        params.sort(key=lambda x: x[0])
        canonical_querystring = urlencode(params)

        canonical_headers = f"host:{self._host}\n"
        signed_headers = "host"
        payload_hash = "UNSIGNED-PAYLOAD"

        canonical_request = (
            f"POST\n{canonical_uri}\n{canonical_querystring}\n"
            f"{canonical_headers}\n{signed_headers}\n{payload_hash}"
        )

        string_to_sign = (
            f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n"
            f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
        )

        signing_key = self._get_signature_key(date_stamp)
        signature = hmac.new(
            signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        init_url = f"{self._endpoint_url}{canonical_uri}?{canonical_querystring}&X-Amz-Signature={signature}"

        try:
            async with httpx.AsyncClient(
                verify=self._verify_tls,
                timeout=self._timeout_seconds,
            ) as client:
                resp = await client.post(
                    init_url,
                    headers={"Content-Type": content_type},
                )
                if resp.status_code != 200:
                    raise ServiceUnavailableError(
                        "Failed to initiate multipart upload with storage provider."
                    )
                text_content = resp.text
                if "<UploadId>" in text_content and "</UploadId>" in text_content:
                    return text_content.split("<UploadId>")[1].split("</UploadId>")[0]
                raise ServiceUnavailableError("Malformed response from storage provider.")
        except httpx.RequestError as exc:
            logger.error("Storage initiate multipart upload failed", exc_info=exc)
            raise ServiceUnavailableError(
                "Object storage service is temporarily unavailable."
            ) from None

    async def complete_multipart_upload(
        self,
        storage_key: str,
        upload_id: str,
        parts: list[dict[str, Any]],
    ) -> StorageObjectMetadata:
        """Complete S3 multipart upload assembling all parts."""
        clean_key = storage_key.lstrip("/")
        now = datetime.now(UTC)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")

        canonical_uri = f"/{self._bucket_name}/{quote(clean_key)}"
        credential_scope = f"{date_stamp}/{self._region}/s3/aws4_request"
        params = [
            ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
            ("X-Amz-Credential", f"{self._access_key}/{credential_scope}"),
            ("X-Amz-Date", amz_date),
            ("X-Amz-Expires", "60"),
            ("X-Amz-SignedHeaders", "host"),
            ("uploadId", upload_id),
        ]
        params.sort(key=lambda x: x[0])
        canonical_querystring = urlencode(params)

        canonical_headers = f"host:{self._host}\n"
        signed_headers = "host"
        payload_hash = "UNSIGNED-PAYLOAD"

        canonical_request = (
            f"POST\n{canonical_uri}\n{canonical_querystring}\n"
            f"{canonical_headers}\n{signed_headers}\n{payload_hash}"
        )

        string_to_sign = (
            f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n"
            f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
        )

        signing_key = self._get_signature_key(date_stamp)
        signature = hmac.new(
            signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        complete_url = f"{self._endpoint_url}{canonical_uri}?{canonical_querystring}&X-Amz-Signature={signature}"

        xml_parts = "".join(
            f"<Part><PartNumber>{p['part_number']}</PartNumber><ETag>{p['etag']}</ETag></Part>"
            for p in sorted(parts, key=lambda x: int(x["part_number"]))
        )
        xml_body = f"<CompleteMultipartUpload>{xml_parts}</CompleteMultipartUpload>"

        try:
            async with httpx.AsyncClient(
                verify=self._verify_tls,
                timeout=self._timeout_seconds,
            ) as client:
                resp = await client.post(
                    complete_url,
                    content=xml_body.encode("utf-8"),
                    headers={"Content-Type": "application/xml"},
                )
                if resp.status_code != 200:
                    raise ServiceUnavailableError(
                        "Failed to complete multipart upload with storage provider."
                    )
                meta = await self.get_object_metadata(storage_key)
                if meta is None:
                    raise ServiceUnavailableError("Failed to retrieve completed object metadata.")
                return meta
        except httpx.RequestError as exc:
            logger.error("Storage complete multipart upload failed", exc_info=exc)
            raise ServiceUnavailableError(
                "Object storage service is temporarily unavailable."
            ) from None

    async def abort_multipart_upload(
        self,
        storage_key: str,
        upload_id: str,
    ) -> bool:
        """Abort S3 multipart upload."""
        clean_key = storage_key.lstrip("/")
        now = datetime.now(UTC)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")

        canonical_uri = f"/{self._bucket_name}/{quote(clean_key)}"
        credential_scope = f"{date_stamp}/{self._region}/s3/aws4_request"
        params = [
            ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
            ("X-Amz-Credential", f"{self._access_key}/{credential_scope}"),
            ("X-Amz-Date", amz_date),
            ("X-Amz-Expires", "60"),
            ("X-Amz-SignedHeaders", "host"),
            ("uploadId", upload_id),
        ]
        params.sort(key=lambda x: x[0])
        canonical_querystring = urlencode(params)

        canonical_headers = f"host:{self._host}\n"
        signed_headers = "host"
        payload_hash = "UNSIGNED-PAYLOAD"

        canonical_request = (
            f"DELETE\n{canonical_uri}\n{canonical_querystring}\n"
            f"{canonical_headers}\n{signed_headers}\n{payload_hash}"
        )

        string_to_sign = (
            f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n"
            f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
        )

        signing_key = self._get_signature_key(date_stamp)
        signature = hmac.new(
            signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        abort_url = f"{self._endpoint_url}{canonical_uri}?{canonical_querystring}&X-Amz-Signature={signature}"

        try:
            async with httpx.AsyncClient(
                verify=self._verify_tls,
                timeout=self._timeout_seconds,
            ) as client:
                resp = await client.delete(abort_url)
                return resp.status_code in {200, 204}
        except httpx.RequestError as exc:
            logger.error("Storage abort multipart upload failed", exc_info=exc)
            raise ServiceUnavailableError(
                "Object storage service is temporarily unavailable."
            ) from None

    async def get_object_bytes(self, storage_key: str) -> bytes:
        """Download object binary content for validation and scanning."""
        download_url = self.generate_presigned_download_url(storage_key, expires_in_seconds=60)
        try:
            async with httpx.AsyncClient(
                verify=self._verify_tls,
                timeout=self._timeout_seconds,
            ) as client:
                resp = await client.get(download_url)
                if resp.status_code == 404:
                    raise ResourceNotFoundError(
                        "Evidence object not found in storage.", code="OBJECT_NOT_FOUND"
                    )
                if resp.status_code != 200:
                    raise ServiceUnavailableError(
                        "Failed to retrieve evidence object from storage."
                    )
                return resp.content
        except httpx.RequestError as exc:
            logger.error("Storage get_object_bytes request failed", exc_info=exc)
            raise ServiceUnavailableError(
                "Object storage service is temporarily unavailable."
            ) from None


class InMemoryStorageClient:
    """In-memory test double for deterministic, isolated unit testing."""

    def __init__(self, endpoint_url: str = "https://s3.test.internal:9000") -> None:
        self.endpoint_url = endpoint_url
        self._objects: dict[str, tuple[bytes, str]] = {}
        self._multiparts: dict[str, dict[str, Any]] = {}

    def generate_presigned_upload_url(
        self,
        storage_key: str,
        content_type: str,
        expires_in_seconds: int = 900,
    ) -> PresignedUploadData:
        expires_at = datetime.now(UTC) + timedelta(seconds=expires_in_seconds)
        url = (
            f"{self.endpoint_url}/upload/{quote(storage_key)}?expires={int(expires_at.timestamp())}"
        )
        return PresignedUploadData(
            upload_url=url,
            upload_method="PUT",
            headers={"Content-Type": content_type},
            expires_at=expires_at,
        )

    def generate_presigned_download_url(
        self,
        storage_key: str,
        expires_in_seconds: int = 300,
    ) -> str:
        expires_at = datetime.now(UTC) + timedelta(seconds=expires_in_seconds)
        return f"{self.endpoint_url}/download/{quote(storage_key)}?expires={int(expires_at.timestamp())}"

    def generate_presigned_part_upload_url(
        self,
        storage_key: str,
        upload_id: str,
        part_number: int,
        expires_in_seconds: int = 900,
    ) -> str:
        expires_at = datetime.now(UTC) + timedelta(seconds=expires_in_seconds)
        return (
            f"{self.endpoint_url}/multipart/{upload_id}/part/{part_number}"
            f"?expires={int(expires_at.timestamp())}"
        )

    async def initiate_multipart_upload(self, storage_key: str, content_type: str) -> str:
        upload_id = uuid.uuid4().hex
        self._multiparts[upload_id] = {
            "key": storage_key,
            "content_type": content_type,
            "parts": {},
        }
        return upload_id

    def store_multipart_part(self, upload_id: str, part_number: int, data: bytes) -> str:
        """Test helper to store a chunk/part for a multipart upload session and return an ETag."""
        if upload_id not in self._multiparts:
            raise BusinessRuleError("Invalid upload ID", code="INVALID_UPLOAD_ID")
        self._multiparts[upload_id]["parts"][part_number] = data
        return hashlib.md5(data, usedforsecurity=False).hexdigest()

    async def complete_multipart_upload(
        self,
        storage_key: str,
        upload_id: str,
        parts: list[dict[str, Any]],
    ) -> StorageObjectMetadata:
        if upload_id not in self._multiparts:
            raise BusinessRuleError("Invalid upload ID", code="INVALID_UPLOAD_ID")
        mp = self._multiparts[upload_id]
        assembled: list[bytes] = []
        for p in sorted(parts, key=lambda x: int(x["part_number"])):
            pn = int(p["part_number"])
            if pn not in mp["parts"]:
                raise BusinessRuleError(f"Missing part {pn}", code="MISSING_PART")
            assembled.append(mp["parts"][pn])
        combined = b"".join(assembled)
        self._objects[storage_key] = (combined, mp["content_type"])
        del self._multiparts[upload_id]
        return StorageObjectMetadata(
            storage_key=storage_key,
            content_length=len(combined),
            content_type=mp["content_type"],
            etag=hashlib.md5(combined, usedforsecurity=False).hexdigest(),
        )

    async def abort_multipart_upload(self, storage_key: str, upload_id: str) -> bool:
        if upload_id in self._multiparts:
            del self._multiparts[upload_id]
            return True
        return False

    async def verify_object_exists(self, storage_key: str) -> bool:
        return storage_key in self._objects

    async def get_object_metadata(self, storage_key: str) -> StorageObjectMetadata | None:
        if storage_key not in self._objects:
            return None
        payload, ctype = self._objects[storage_key]
        return StorageObjectMetadata(
            storage_key=storage_key,
            content_length=len(payload),
            content_type=ctype,
            etag=hashlib.md5(payload, usedforsecurity=False).hexdigest(),
        )

    async def get_object_bytes(self, storage_key: str) -> bytes:
        if storage_key not in self._objects:
            raise ResourceNotFoundError("Object not found in storage.", code="OBJECT_NOT_FOUND")
        return self._objects[storage_key][0]

    async def delete_object(self, storage_key: str) -> bool:
        if storage_key in self._objects:
            del self._objects[storage_key]
            return True
        return False

    def store_mock_object(self, storage_key: str, payload: bytes, content_type: str) -> None:
        """Test helper to inject mock data into the in-memory store."""
        self._objects[storage_key] = (payload, content_type)

    async def put_object(self, storage_key: str, payload: bytes, content_type: str) -> None:
        """Async test helper to inject mock data into the in-memory store."""
        self.store_mock_object(storage_key, payload, content_type)

    async def put_part(
        self, storage_key: str, upload_id: str, part_number: int, data: bytes
    ) -> str:
        """Async test helper to store a chunk/part for a multipart upload session and return an ETag."""
        return self.store_multipart_part(upload_id, part_number, data)
