import os
import sys
import nv_attestation_sdk.attestation as attestation_module

# Suppress stdout
class Silence:
    def write(self, msg):
        pass

    def flush(self):
        pass

def main():
    # Redirect stdout to silence internal messages

    try:
        old_stdout = sys.stdout
        sys.stdout = Silence()
        
        client_name = "AttestationAgent"
        attestation_class = attestation_module.Attestation(client_name)
        
        devices = attestation_module.Devices
        environment = attestation_module.Environment
        
        attestation_class.add_verifier(devices.GPU, environment.LOCAL, "", "")
        result = attestation_class.attest()
        
        sys.stdout = old_stdout

        if result:
            token = attestation_class.get_token()
            if token:
                print(token)  # Output the token for Rust to capture
                return
        
        print("GPU Attestation failed or no token obtained", file=sys.stderr)
        sys.exit(1)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()