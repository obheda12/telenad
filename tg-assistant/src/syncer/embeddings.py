"""
Embedding generation for semantic search.

Provides local on-device embeddings using ``all-MiniLM-L6-v2`` via
sentence-transformers (384-dim vectors).  No external API calls required.

The ``EmbeddingProvider`` ABC allows swapping in a different backend later
without changing the rest of the codebase.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import List

logger = logging.getLogger("syncer.embeddings")


class EmbeddingProvider(ABC):
    """Abstract base class for embedding generators."""

    @property
    @abstractmethod
    def dimension(self) -> int:
        """Dimensionality of the embedding vectors produced."""
        ...

    @abstractmethod
    async def generate_embedding(self, text: str) -> List[float]:
        """Generate a single embedding vector for *text*."""
        ...

    @abstractmethod
    async def batch_generate(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings for multiple texts in one call."""
        ...


class LocalEmbeddings(EmbeddingProvider):
    """Embedding provider using ``all-MiniLM-L6-v2`` via sentence-transformers.

    Runs entirely on-device — no network calls.

    Args:
        model_name: HuggingFace model identifier.
        device: ``"cpu"`` or ``"cuda"``.
    """

    _DIMENSION: int = 384

    def __init__(
        self,
        model_name: str = "all-MiniLM-L6-v2",
        device: str = "cpu",
    ) -> None:
        self._model_name = model_name
        self._device = device
        self._model = None  # lazy-loaded

    def _load_model(self) -> None:
        """Lazy-load the sentence-transformers model."""
        if self._model is not None:
            return
        from sentence_transformers import SentenceTransformer

        self._model = SentenceTransformer(self._model_name, device=self._device)
        logger.info("Loaded local embedding model: %s", self._model_name)

    @property
    def dimension(self) -> int:
        return self._DIMENSION

    async def generate_embedding(self, text: str) -> List[float]:
        """Generate embedding locally using sentence-transformers."""
        self._load_model()
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, self._model.encode, text)
        return result.tolist()

    async def batch_generate(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings locally for a batch."""
        if not texts:
            return []
        self._load_model()
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(None, self._model.encode, texts)
        return [r.tolist() for r in results]


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def create_embedding_provider(config: dict) -> EmbeddingProvider:
    """Create the embedding provider based on configuration.

    Args:
        config: The ``[embeddings]`` section from settings.toml.

    Returns:
        An ``EmbeddingProvider`` instance.
    """
    logger.info("Using local embeddings (model=%s)", config.get("local_model", "all-MiniLM-L6-v2"))
    return LocalEmbeddings(
        model_name=config.get("local_model", "all-MiniLM-L6-v2"),
        device="cpu",
    )
