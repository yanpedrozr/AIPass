from flask import jsonify

from . import bp


@bp.get("/status")
def status():
    return jsonify(module="crypto", status="not implemented")
