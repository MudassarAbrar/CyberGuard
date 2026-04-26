import typer
from rich.console import Console

app = typer.Typer()
console = Console()


@app.command()
def scan(path: str):
    """Scan a project path for vulnerabilities."""
    console.print(f"[bold green]Scanning {path}...[/bold green]")


if __name__ == "__main__":
    app()
