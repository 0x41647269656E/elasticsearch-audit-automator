"""Appel du modèle Anthropic.

Isolé du reste : `analysis.py` ne connaît que le protocole `Caller`, si bien que
toute la logique d'analyse se teste sans réseau ni clé d'API.
"""
from __future__ import annotations

import json
from typing import Any, Dict, Optional

from .analysis import ModelOutcome

MODEL = "claude-opus-5"
EFFORT = "high"
MAX_TOKENS = 32_000

# Sans ce repli, un refus des classificateurs de sécurité vide un axe entier.
# L'axe `securite` transmet rôles, comptes et métadonnées de clés d'API : le cas
# est attendu, pas exceptionnel.
FALLBACK_BETA = "server-side-fallback-2026-07-01"


class AnthropicCaller:
    """Implémente le protocole `Caller` au-dessus du SDK Anthropic."""

    def __init__(
        self,
        client: Any = None,
        model: str = MODEL,
        effort: str = EFFORT,
        max_tokens: int = MAX_TOKENS,
        fallback: bool = True,
    ) -> None:
        if client is None:
            import anthropic

            client = anthropic.Anthropic()
        self.client = client
        self.model = model
        self.effort = effort
        self.max_tokens = max_tokens
        self.fallback = fallback

    def count_tokens(self, system: str, user: str) -> int:
        response = self.client.messages.count_tokens(
            model=self.model,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return response.input_tokens

    def _request_kwargs(self, system: str, user: str, schema: Dict[str, Any]) -> Dict[str, Any]:
        kwargs: Dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            # Le préfixe système est identique pour les dix axes : c'est lui
            # qu'on met en cache, pas les artefacts propres à chaque axe.
            "system": [
                {"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}
            ],
            "messages": [{"role": "user", "content": user}],
            "output_config": {
                "effort": self.effort,
                "format": {"type": "json_schema", "schema": schema},
            },
        }
        if self.fallback:
            kwargs["betas"] = [FALLBACK_BETA]
            kwargs["fallbacks"] = "default"
        return kwargs

    def complete(self, system: str, user: str, schema: Dict[str, Any]) -> ModelOutcome:
        kwargs = self._request_kwargs(system, user, schema)

        # Streaming : les entrées d'un axe peuvent peser des centaines de
        # milliers de jetons, largement de quoi dépasser le délai HTTP.
        with self.client.beta.messages.stream(**kwargs) as stream:
            message = stream.get_final_message()

        # À vérifier avant de lire `content` : un refus renvoie un 200 dont le
        # contenu est vide ou partiel.
        if getattr(message, "stop_reason", None) == "refusal":
            details = getattr(message, "stop_details", None)
            return ModelOutcome(refusal=getattr(details, "category", None) or "non précisé")

        text = next(
            (b.text for b in message.content if getattr(b, "type", None) == "text"), None
        )
        if not text:
            return ModelOutcome()
        return ModelOutcome(data=json.loads(text))


def resolve_credentials() -> Optional[str]:
    """Retourne None si le SDK saura s'authentifier, sinon un message d'aide.

    Le SDK résout aussi bien ANTHROPIC_API_KEY qu'un profil `ant auth login` :
    l'absence de variable d'environnement ne signifie pas l'absence de clé.
    """
    import os

    if os.getenv("ANTHROPIC_API_KEY") or os.getenv("ANTHROPIC_AUTH_TOKEN"):
        return None
    try:
        import anthropic

        anthropic.Anthropic()  # lève si aucune source d'identifiants n'est trouvée
        return None
    except Exception:
        return (
            "Aucun identifiant Anthropic trouvé. Renseignez ANTHROPIC_API_KEY dans .env, "
            "ou connectez-vous avec `ant auth login`."
        )
