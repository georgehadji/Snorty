"""`python -m snorty.sensor`: the headless runner lives in `snorty.headless`."""

from snorty.headless import main

if __name__ == "__main__":
    raise SystemExit(main())
