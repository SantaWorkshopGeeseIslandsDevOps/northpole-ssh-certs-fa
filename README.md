# northpole-ssh-certs-fa

## Description

In an effort to better secure our server infrastructure I asked ChatNPT for help and it proposed switching from SSH keys to SSH certificates for authentication. Better yet, it also suggested I set up a self-service website to allow elves to sign their own SSH keys! Such a time saver! 🎉

## ChatNPT prompts

**Prompt**:
We currently use SSH keys for authentication to our various servers. Is there anything else we can implement to secure the SSH authentication process even more?

**ChatNPT**:
1. Use Strong SSH Keys: Ensure that your SSH keys are strong and secure. This typically means using RSA keys of at least 2048 bits, but ideally 4096 bits. Avoid using DSA keys as they are considered less secure.
2. Disable Password Authentication: Rely solely on SSH keys for authentication and disable password-based logins. This prevents attacks like brute-forcing passwords.
3. Keep Software Updated: Regularly update your SSH server software to the latest version to ensure that any security patches and updates are applied.
4. Harden SSH Configuration: Customize your `sshd_config` file to disable weak ciphers, enforce strong MAC algorithms, and disable features like X11 forwarding unless necessary.
5. Implement SSH Certificate Authentication: Instead of traditional SSH keys, use SSH certificates. This method allows for centralized management of authentication and can enforce validity periods for keys.

**Prompt**:
I've already implemented suggestions 1 to 4, but 5 sounds interesting. Can you provide more detail?

**ChatNPT**:
SSH certificates offer a more secure and manageable method of SSH authentication. In this system, a trusted Certificate Authority (CA) issues digital certificates to users. These certificates, signed by the CA, replace traditional SSH keys for authentication. They not only centralize control but also enable scalable management, including embedding principals for role-based access. The certificates have set validity periods, thereby enhancing security by limiting the lifespan of access credentials.

Implementing SSH certificates requires setting up a CA, configuring SSH servers to recognize and trust this CA, and creating a process for issuing and managing certificates. This method is particularly advantageous in large or complex environments, as it simplifies the management of SSH keys, supports granular, role-based access control through principals, and improves audit capabilities.

**Prompt**:
Updating our SSH configuration should be easy, but issuing and managing the certificates sounds like a lot of additional work. Is there any way to simplify that process?

**ChatNPT**:
You are correct. Certificate management is quite a complex process. However, you can implement a self-service website which allows Santa and the elves to submit their public SSH keys and automatically creates a signed SSH certificate for them. Below is some sample Python code which you can deploy to a cloud environment like AWS, Azure, or Google Cloud.

--- Sample code removed (see finalized [`function_app.py`](./function_app.py)) ---

And remember... **Swap your winter hat for a snorkel mask; Geese Islands is the cheat code to beat the cold. Unlock the ultimate level in vacation mode!** 🪿🏝️
