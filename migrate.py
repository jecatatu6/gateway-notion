import subprocess
import sys

def run_migrations():
    try:
        print("Executando migrações do Prisma...")
        result = subprocess.run(["prisma", "migrate", "deploy"], check=True, capture_output=True, text=True)
        print(result.stdout)
        print("Migrações aplicadas com sucesso.")
    except subprocess.CalledProcessError as e:
        print("Erro ao aplicar migrações:")
        print(e.stderr)
        sys.exit(1)

if __name__ == "__main__":
    run_migrations()