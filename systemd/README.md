# systemd user service

This folder contains an optional one-shot user service that runs the startup random selector once per user session on headless systems without an XDG desktop environment (for desktop environments, use `a` in the TUI instead).

## Install

1. Build and install the binary:

   ```bash
   cargo install --path . --root "$HOME/.local"
   ```

2. Install the unit file:

   ```bash
   mkdir -p "$HOME/.config/systemd/user"
   cp systemd/neutron-startup-random.service "$HOME/.config/systemd/user/"
   ```

3. Enable the service:

   ```bash
   systemctl --user daemon-reload
   systemctl --user enable neutron-startup-random.service
   ```

4. Optional: test immediately:

   ```bash
   systemctl --user start neutron-startup-random.service
   journalctl --user -u neutron-startup-random.service -n 50 --no-pager
   ```
