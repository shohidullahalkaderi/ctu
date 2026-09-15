# docker build --tag ctu-privilege-escalation .
# docker run --rm -it --user root ctu-privilege-escalation bash -c "cd /lab/exploits && bash ctu.sh"
FROM archlinux:latest

# Update system and install essential development tools, gdb, and sudo
RUN pacman -Syu --noconfirm base-devel gdb sudo

# Create unprivileged labuser for running the exploit
RUN useradd -m -s /bin/bash labuser \
    && echo "labuser ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Set working directory inside container
WORKDIR /lab

# Copy source code and exploit scripts
COPY src/ /lab/src/
COPY exploits/ /lab/exploits/

# Set ownership and executable permissions for exploit scripts
RUN chown -R labuser:labuser /lab/exploits && chmod +x /lab/exploits/*.sh

# Default command opens an interactive shell in the exploits folder as labuser
WORKDIR /lab/exploits
USER labuser
CMD ["bash"]