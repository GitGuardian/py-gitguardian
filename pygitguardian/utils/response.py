from requests import Response, codes

from ..models import Detail


def load_detail(resp: Response) -> Detail:
    """
    load_detail loads a Detail from a response
    be it JSON or html.

    :param resp: API response
    :type resp: Response
    :return: detail object of response
    :rtype: Detail
    """
    if resp.headers["content-type"] == "application/json":
        data = resp.json()
    else:
        data = {"detail": resp.text}

    return Detail.from_dict(data)


def is_ok(resp: Response) -> bool:
    """
    is_ok returns True is the API responded with 200
    and the content type is JSON.
    """
    return (
        resp.headers["content-type"] == "application/json"
        and resp.status_code == codes.ok
    )


def is_create_ok(resp: Response) -> bool:
    """
    is_create_ok returns True if the API returns code 201
    and the content type is JSON.
    """
    return (
        resp.headers["content-type"] == "application/json"
        and resp.status_code == codes.created
    )


