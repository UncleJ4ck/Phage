# Phage evo: `python -m phage.evo` entrypoint.
# License: Apache-2.0 License

from .runner import main

if __name__ == "__main__":
    raise SystemExit(main())
