"""Unit tests for Phase 63: Safe Video Metadata Extraction and Deterministic Preprocessing."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from ai_services.video.metadata import (
    VideoMetadata,
    extract_video_metadata_from_bytes,
    extract_video_metadata_from_file,
)
from ai_services.video.preprocessing import (
    generate_frame_sampling_plan,
    isolated_video_temp_dir,
    validate_video_file_constraints,
)
from ai_services.violence_detection.requirements import AIOperationalConstraints
from backend.app.core.exceptions import VideoProcessingError


def _build_minimal_mp4_bytes(
    duration_seconds: float = 12.0,
    timescale: int = 1000,
    width: int = 1280,
    height: int = 720,
    codec: str = "avc1",
) -> bytes:
    """Helper to synthesize valid minimal ISO-BMFF MP4 bytes with ftyp and moov boxes."""
    # 1. ftyp box
    ftyp_payload = b"isom" + struct.pack(">I", 512) + b"isom" + b"iso2" + b"mp41"
    ftyp_box = struct.pack(">I4s", len(ftyp_payload) + 8, b"ftyp") + ftyp_payload

    # 2. mvhd box (inside moov)
    duration_ticks = int(duration_seconds * timescale)
    # version 0: 4 bytes creation, 4 bytes mod, 4 bytes timescale, 4 bytes duration, 80 bytes reserved
    mvhd_payload = (
        b"\x00\x00\x00\x00"  # version 0, flags 0
        + struct.pack(">II", 0, 0)  # creation, modification
        + struct.pack(">II", timescale, duration_ticks)
        + b"\x00" * 80  # reserved / matrix
    )
    mvhd_box = struct.pack(">I4s", len(mvhd_payload) + 8, b"mvhd") + mvhd_payload

    # 3. tkhd box (inside trak)
    # width and height at end as 16.16 fixed point numbers
    tkhd_payload = (
        b"\x00\x00\x00\x07"  # version 0, flags 7 (enabled)
        + b"\x00" * 76  # reserved
        + struct.pack(">II", width << 16, height << 16)
    )
    tkhd_box = struct.pack(">I4s", len(tkhd_payload) + 8, b"tkhd") + tkhd_payload

    # 4. stsd box (inside stbl) with visual sample entry
    # VisualSampleEntry has width/height at offset +24 / +26 from format fourcc
    sample_entry_payload = (
        b"\x00" * 6  # reserved
        + struct.pack(">H", 1)  # data reference index
        + b"\x00" * 16  # pre-defined, reserved
        + struct.pack(">HH", width, height)
        + b"\x00" * 46  # horiz/vert resolution, compressor name, depth
    )
    sample_entry_box = (
        struct.pack(">I4s", len(sample_entry_payload) + 8, codec.encode("ascii")[:4])
        + sample_entry_payload
    )

    stsd_payload = (
        b"\x00\x00\x00\x00"  # version 0, flags 0
        + struct.pack(">I", 1)  # entry count
        + sample_entry_box
    )
    stsd_box = struct.pack(">I4s", len(stsd_payload) + 8, b"stsd") + stsd_payload

    # stbl box
    stbl_payload = stsd_box
    stbl_box = struct.pack(">I4s", len(stbl_payload) + 8, b"stbl") + stbl_payload

    # minf box
    minf_payload = stbl_box
    minf_box = struct.pack(">I4s", len(minf_payload) + 8, b"minf") + minf_payload

    # mdia box
    mdia_payload = minf_box
    mdia_box = struct.pack(">I4s", len(mdia_payload) + 8, b"mdia") + mdia_payload

    # trak box
    trak_payload = tkhd_box + mdia_box
    trak_box = struct.pack(">I4s", len(trak_payload) + 8, b"trak") + trak_payload

    # moov box
    moov_payload = mvhd_box + trak_box
    moov_box = struct.pack(">I4s", len(moov_payload) + 8, b"moov") + moov_payload

    return ftyp_box + moov_box


@pytest.mark.unit
class TestVideoMetadataExtraction:
    """Verify safe ISO-BMFF MP4 binary parsing without external processes."""

    def test_extract_metadata_from_valid_mp4_bytes(self) -> None:
        data = _build_minimal_mp4_bytes(
            duration_seconds=14.5,
            width=1920,
            height=1080,
            codec="avc1",
        )
        meta = extract_video_metadata_from_bytes(data)

        assert meta.duration_seconds == 14.5
        assert meta.width == 1920
        assert meta.height == 1080
        assert meta.codec == "avc1"
        assert meta.container == "isom"
        assert meta.file_size_bytes == len(data)

    def test_extract_metadata_from_file_on_disk(self, tmp_path: Path) -> None:
        data = _build_minimal_mp4_bytes(duration_seconds=8.0, width=640, height=480)
        file_path = tmp_path / "test_sample.mp4"
        file_path.write_bytes(data)

        meta = extract_video_metadata_from_file(file_path)
        assert meta.duration_seconds == 8.0
        assert meta.width == 640
        assert meta.height == 480

    def test_extract_metadata_rejects_truncated_data(self) -> None:
        with pytest.raises(VideoProcessingError, match="too small"):
            extract_video_metadata_from_bytes(b"short")

    def test_extract_metadata_rejects_missing_moov_box(self) -> None:
        # Only ftyp box
        ftyp_payload = b"isom" + struct.pack(">I", 512) + b"isom"
        data = struct.pack(">I4s", len(ftyp_payload) + 8, b"ftyp") + ftyp_payload

        with pytest.raises(VideoProcessingError, match="missing 'moov'"):
            extract_video_metadata_from_bytes(data)

    def test_extract_metadata_nonexistent_file(self) -> None:
        with pytest.raises(VideoProcessingError, match="not found"):
            extract_video_metadata_from_file("nonexistent_video.mp4")

    def test_extract_metadata_empty_file(self, tmp_path: Path) -> None:
        empty_file = tmp_path / "empty.mp4"
        empty_file.write_bytes(b"")

        with pytest.raises(VideoProcessingError, match="empty or corrupted"):
            extract_video_metadata_from_file(empty_file)


@pytest.mark.unit
class TestVideoPreprocessingAndSampling:
    """Verify deterministic sampling plan, constraints, and temp directory management."""

    def test_sampling_plan_short_video_one_fps(self) -> None:
        """Video <= 64s samples at 1 fps."""
        meta = VideoMetadata(
            duration_seconds=10.0,
            width=1280,
            height=720,
            fps=30.0,
            codec="avc1",
            container="isom",
            file_size_bytes=1000,
            timescale=1000,
        )
        plan = generate_frame_sampling_plan(meta)

        assert plan.target_sample_count == 10
        assert plan.sample_timestamps == (0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0)
        assert plan.target_resolution == (224, 224)
        assert plan.normalize_mean == (0.485, 0.456, 0.406)
        assert plan.normalize_std == (0.229, 0.224, 0.225)

    def test_sampling_plan_long_video_uniform_sampling(self) -> None:
        """Video > 64s samples uniformly across total duration."""
        meta = VideoMetadata(
            duration_seconds=128.0,
            width=1280,
            height=720,
            fps=30.0,
            codec="avc1",
            container="isom",
            file_size_bytes=5000,
            timescale=1000,
        )
        plan = generate_frame_sampling_plan(meta)

        assert plan.target_sample_count == 64
        assert len(plan.sample_timestamps) == 64
        # First timestamp is 0.0, second is 2.0, etc.
        assert plan.sample_timestamps[0] == 0.0
        assert plan.sample_timestamps[1] == 2.0

    def test_validate_video_file_constraints_success(self, tmp_path: Path) -> None:
        data = _build_minimal_mp4_bytes(duration_seconds=20.0, codec="avc1")
        file_path = tmp_path / "valid.mp4"
        file_path.write_bytes(data)

        meta = validate_video_file_constraints(file_path)
        assert meta.duration_seconds == 20.0
        assert meta.codec == "avc1"

    def test_validate_video_file_constraints_duration_exceeded(self, tmp_path: Path) -> None:
        data = _build_minimal_mp4_bytes(duration_seconds=700.0, codec="avc1")
        file_path = tmp_path / "too_long.mp4"
        file_path.write_bytes(data)

        with pytest.raises(VideoProcessingError, match=r"duration .* exceeds maximum"):
            validate_video_file_constraints(file_path)

    def test_validate_video_file_constraints_size_exceeded(self, tmp_path: Path) -> None:
        data = _build_minimal_mp4_bytes(duration_seconds=5.0)
        file_path = tmp_path / "oversize.mp4"
        file_path.write_bytes(data)

        tight_constraints = AIOperationalConstraints(max_file_size_bytes=10)
        with pytest.raises(VideoProcessingError, match=r"file size .* exceeds maximum"):
            validate_video_file_constraints(file_path, constraints=tight_constraints)

    def test_validate_video_file_constraints_codec_rejected(self, tmp_path: Path) -> None:
        data = _build_minimal_mp4_bytes(duration_seconds=5.0, codec="vp09")
        file_path = tmp_path / "unsupported_codec.mp4"
        file_path.write_bytes(data)

        with pytest.raises(VideoProcessingError, match="codec 'vp09' is not supported"):
            validate_video_file_constraints(file_path)

    def test_isolated_video_temp_dir_lifecycle(self) -> None:
        captured_path: Path | None = None
        with isolated_video_temp_dir() as temp_dir:
            captured_path = temp_dir
            assert temp_dir.is_dir()
            test_file = temp_dir / "scratch.bin"
            test_file.write_bytes(b"temp data")
            assert test_file.is_file()

        assert captured_path is not None
        assert not captured_path.exists()
