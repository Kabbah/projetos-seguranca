# ==============================================================================
# MAIN PARA O AS
#
# Autor: Victor Barpp Gomes
# Data: 2018/09/15
# ==============================================================================

from auth_server import AuthServer

# ==============================================================================

def main():
    server = AuthServer()
    server.start()

if __name__ == "__main__":
    main()

# ==============================================================================
