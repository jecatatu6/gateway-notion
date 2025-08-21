import subprocess
import sys

def run_migrations():
    print("Executando migrações do Prisma...")
    subprocess.run(
        [sys.executable, "-m", "prisma", "migrate", "deploy"],
        check=True
    )
    print("Migrações aplicadas com sucesso.")

if __name__ == "__main__":
    run_migrations()
