# NEURAL DETECT repository notes

- The project runs in WSL Ubuntu 22.04 at /home/ghost/jarvis. Run Docker and Linux commands in that distro; do not assume the Windows Docker context is the intended one.
- Before and after a phase, inspect docker compose ps from the project directory and preserve containers belonging to other projects.
- If a change affects the frontend, run its production build and visually inspect the rendered page in a browser. Capture a screenshot and report the view and result in the phase report. Capture and inspect a screenshot for every frontend phase before marking that phase complete.
- Validate API routes and database migrations against the running Compose services when available. Never claim an integration works based only on YAML parsing or offline SQL output.
- Keep .env local and ignored; never copy generated development secrets into tracked files.
