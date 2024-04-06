import sys
from make_token import create_assertion
import requests
import urllib.parse
import json
import jwt


def satellite_auth(
        satellite_url: str,
        client_id: str,
        assertion: str,
) -> str:
    atype = "urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"

    payload = "&".join([
        "grant_type=client_credentials",
        f"client_assertion_type={atype}",
        f"client_id={client_id}",
        "scope=iSHARE",
        f"client_assertion={assertion}",
    ])

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    response = requests.request("POST",
                                urllib.parse.urljoin(
                                    satellite_url,
                                    "/connect/token"
                                ),
                                headers=headers,
                                data=payload)

    print(response.status_code)
    print("text", response.text)
    response.raise_for_status()
    return response.json()["access_token"]


def satellite_get_trusted_list(
        satellite_url: str,
        access_token: str,
):
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {access_token}",
    }

    response = requests.request("GET",
                                urllib.parse.urljoin(
                                    satellite_url,
                                    "/trusted_list"
                                ),
                                headers=headers)
    response.raise_for_status()
    tk = response.json()["trusted_list_token"]

    # verify_signature true does not work
    return jwt.decode(tk, options={"verify_signature": False})


def satellite_get_parties(
        satellite_url: str,
        access_token: str,
        party_eori: str = "*",
):
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {access_token}",
    }

    query = "&".join([
        f"eori={party_eori}",
        "active_only=true",
    ])

    response = requests.request("GET",
                                urllib.parse.urljoin(
                                    satellite_url,
                                    f"/parties?{query}"
                                ),
                                headers=headers)
    response.raise_for_status()
    tk = response.json()["parties_token"]

    # verify_signature true does not work
    return jwt.decode(tk, options={"verify_signature": False})


def main():
    import argparse

    parser = argparse.ArgumentParser("Makes client assertion for iShare")
    parser.add_argument(
        "-t", "--target_id",
        help="For which target (aud) is this client_assertion?",
        required=True)
    parser.add_argument(
        "-c", "--cert",
        help="Certificate file",
        required=True)
    parser.add_argument(
        "-p", "--password",
        help="Certificate password",
        required=False)
    parser.add_argument(
        "-s", "--satellite",
        help="URL of satellite",
        required=True)

    args = parser.parse_args()

    if not args.password:
        args.password = input("Enter password:")

    if not args.password or args.password == '':
        print('no password')
        return 1

    assertion, client_id = create_assertion(
        cert_path=args.cert,
        password=args.password,
        target_id=args.target_id,
    )

    print('client id: ', client_id)
    access_token = satellite_auth(
        satellite_url=args.satellite,
        assertion=assertion,
        client_id=client_id,
    )

    print('here')

    if False:
        trusted_list = satellite_get_trusted_list(
            satellite_url=args.satellite,
            access_token=access_token,
        )

        print(json.dumps(trusted_list))

    else:

        print('there')
        parties = satellite_get_parties(
            satellite_url=args.satellite,
            access_token=access_token,
            party_eori="*",
        )

        print(json.dumps(parties))


if __name__ == "__main__":
    sys.exit(main())
