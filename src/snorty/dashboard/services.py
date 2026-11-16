"""FastAPI glue: hand the services bundle to controllers through `Depends`."""

from typing import Annotated

from fastapi import Depends, Request

from snorty.services import Services


def get_services(request: Request) -> Services:
    services: Services = request.app.state.services
    return services


Svc = Annotated[Services, Depends(get_services)]
