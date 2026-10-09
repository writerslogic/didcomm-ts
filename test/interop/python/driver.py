"""didcomm-python counterparty for didcomm-ts interop tests.

Reads one JSON request on stdin and writes one JSON response on stdout:
  {"op": "pack", "didDocs": [...], "secrets": [...], "message": {...},
   "to": DID, "from": DID|null, "signBy": DID|null, "enc": "A256CBC-HS512"|"A256GCM"|"XC20P",
   "protectSender": bool}
  {"op": "unpack", "didDocs": [...], "secrets": [...], "envelope": "<json>"}
Secrets use the didcomm-ts Secret shape ({id, type, privateKeyJwk}).
"""

import asyncio
import json
import sys
import warnings

warnings.filterwarnings("ignore")

from didcomm.common.algorithms import AnonCryptAlg  # noqa: E402
from didcomm.common.resolvers import ResolversConfig  # noqa: E402
from didcomm.did_doc.did_doc import DIDDoc  # noqa: E402
from didcomm.did_doc.did_resolver_in_memory import DIDResolverInMemory  # noqa: E402
from didcomm.pack_encrypted import PackEncryptedConfig, pack_encrypted  # noqa: E402
from didcomm.secrets.secrets_resolver_in_memory import SecretsResolverInMemory  # noqa: E402
from didcomm.secrets.secrets_util import jwk_to_secret  # noqa: E402
from didcomm.unpack import unpack  # noqa: E402

ANON_ALGS = {
    "A256CBC-HS512": AnonCryptAlg.A256CBC_HS512_ECDH_ES_A256KW,
    "A256GCM": AnonCryptAlg.A256GCM_ECDH_ES_A256KW,
    "XC20P": AnonCryptAlg.XC20P_ECDH_ES_A256KW,
}


def resolvers(request):
    docs = [DIDDoc.deserialize(doc) for doc in request["didDocs"]]
    secrets = [jwk_to_secret({**s["privateKeyJwk"], "kid": s["id"]}) for s in request["secrets"]]
    return ResolversConfig(
        secrets_resolver=SecretsResolverInMemory(secrets),
        did_resolver=DIDResolverInMemory(docs),
    )


async def run(request):
    config = resolvers(request)
    if request["op"] == "pack":
        result = await pack_encrypted(
            resolvers_config=config,
            message=request["message"],
            to=request["to"],
            frm=request.get("from"),
            sign_frm=request.get("signBy"),
            pack_config=PackEncryptedConfig(
                enc_alg_anon=ANON_ALGS[request.get("enc", "A256CBC-HS512")],
                protect_sender_id=request.get("protectSender", False),
                forward=False,
            ),
        )
        return {"envelope": result.packed_msg}
    if request["op"] == "unpack":
        result = await unpack(config, request["envelope"], deserializer=lambda obj: obj)
        meta = result.metadata
        return {
            "message": result.message,
            "encryptedFrom": meta.encrypted_from,
            "encryptedTo": meta.encrypted_to,
            "signFrom": meta.sign_from,
            "authenticated": meta.authenticated,
            "nonRepudiation": meta.non_repudiation,
        }
    raise ValueError(f"unknown op {request['op']}")


def main():
    request = json.load(sys.stdin)
    try:
        response = asyncio.run(run(request))
    except Exception as exc:  # reported to the caller, which fails the test
        response = {"error": f"{type(exc).__name__}: {exc}"}
    json.dump(response, sys.stdout, default=str)


if __name__ == "__main__":
    main()
