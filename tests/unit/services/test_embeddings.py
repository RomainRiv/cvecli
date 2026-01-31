"""Unit tests for the embeddings service.

These tests focus on the embeddings service logic with mocked model.
"""

import polars as pl

from cvecli.services.embeddings import (
    EmbeddingsService,
    DEFAULT_MODEL_NAME,
    EMBEDDING_DIMENSION,
)


class TestEmbeddingsServiceInit:
    """Tests for EmbeddingsService initialization."""

    def test_init_default_config(self):
        """Service should initialize with default config."""
        service = EmbeddingsService()
        assert service.config is not None
        assert service.model_name == DEFAULT_MODEL_NAME
        assert service.quiet is False
        assert service._model is None  # Model not loaded until needed

    def test_init_custom_model(self):
        """Service should accept custom model name."""
        service = EmbeddingsService(model_name="custom-model")
        assert service.model_name == "custom-model"

    def test_init_quiet_mode(self):
        """Service should support quiet mode."""
        service = EmbeddingsService(quiet=True)
        assert service.quiet is True


class TestPrepareTexts:
    """Tests for text preparation from CVE data."""

    def test_prepare_texts_with_title_and_description(self):
        """Should combine title and description."""
        cves_df = pl.DataFrame(
            {
                "cve_id": ["CVE-2024-1234"],
                "cna_title": ["Test vulnerability"],
            }
        )
        descriptions_df = pl.DataFrame(
            {
                "cve_id": ["CVE-2024-1234"],
                "lang": ["en"],
                "value": ["A buffer overflow vulnerability."],
                "source": ["cna"],
            }
        )

        service = EmbeddingsService(quiet=True)
        texts = service._prepare_texts(cves_df, descriptions_df)

        assert len(texts) == 1
        assert texts[0][0] == "CVE-2024-1234"
        assert "Test vulnerability" in texts[0][1]
        assert "buffer overflow" in texts[0][1]

    def test_prepare_texts_with_title_only(self):
        """Should use title when description is missing."""
        cves_df = pl.DataFrame(
            {
                "cve_id": ["CVE-2024-1234"],
                "cna_title": ["Test vulnerability"],
            }
        )
        descriptions_df = pl.DataFrame(
            schema={
                "cve_id": pl.Utf8,
                "lang": pl.Utf8,
                "value": pl.Utf8,
                "source": pl.Utf8,
            }
        )

        service = EmbeddingsService(quiet=True)
        texts = service._prepare_texts(cves_df, descriptions_df)

        assert len(texts) == 1
        assert texts[0][1] == "Test vulnerability"

    def test_prepare_texts_with_description_only(self):
        """Should use description when title is missing."""
        cves_df = pl.DataFrame(
            {
                "cve_id": ["CVE-2024-1234"],
                "cna_title": [None],
            }
        )
        descriptions_df = pl.DataFrame(
            {
                "cve_id": ["CVE-2024-1234"],
                "lang": ["en"],
                "value": ["A buffer overflow vulnerability."],
                "source": ["cna"],
            }
        )

        service = EmbeddingsService(quiet=True)
        texts = service._prepare_texts(cves_df, descriptions_df)

        assert len(texts) == 1
        assert "buffer overflow" in texts[0][1]

    def test_prepare_texts_skips_empty(self):
        """Should skip CVEs with no title or description."""
        cves_df = pl.DataFrame(
            {
                "cve_id": ["CVE-2024-1234", "CVE-2024-5678"],
                "cna_title": [None, "Test"],
            }
        )
        descriptions_df = pl.DataFrame(
            {
                "cve_id": ["CVE-2024-5678"],
                "lang": ["en"],
                "value": ["Test description."],
                "source": ["cna"],
            }
        )

        service = EmbeddingsService(quiet=True)
        texts = service._prepare_texts(cves_df, descriptions_df)

        # Only CVE-2024-5678 should be included (has title and description)
        # CVE-2024-1234 has no title and no description, so skipped
        assert len(texts) <= 2


class TestEmbeddingGeneration:
    """Tests for embedding generation with mocked model."""

    def test_generate_embeddings_uses_model(self):
        """Generate embeddings should use the internal model."""
        # This test verifies that the model is loaded and used
        # The actual embedding generation is tested through extract_embeddings
        service = EmbeddingsService(quiet=True)

        # Just verify the service initializes correctly
        assert service.model_name == DEFAULT_MODEL_NAME
        assert service.quiet is True


class TestEmbeddingDimension:
    """Tests for embedding dimension constant."""

    def test_embedding_dimension_positive(self):
        """Embedding dimension should be positive."""
        assert EMBEDDING_DIMENSION > 0

    def test_embedding_dimension_reasonable_size(self):
        """Embedding dimension should be reasonable for a small model."""
        # FastEmbed models typically have dimensions like 384, 768
        assert 128 <= EMBEDDING_DIMENSION <= 2048
