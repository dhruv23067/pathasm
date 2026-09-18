# pathasm/src/cli.py
import os
import sys
import click
import subprocess

@click.group()
def main():
    """🥷 PathAsm: Open-Source Attack Path Explorer & AD Telemetry Evasion Engine"""
    pass

@main.command()
def view():
    """Launch the interactive graphical dashboard inside your default web browser."""
    click.echo(click.style("[*] Bootstrapping PathAsm Visual Matrix Frame...", fg="cyan"))
    
    # Locate dashboard.py dynamically within the installed module package location
    src_dir = os.path.dirname(os.path.abspath(__file__))
    dashboard_path = os.path.join(src_dir, "dashboard.py")
    
    if not os.path.exists(dashboard_path):
        click.echo(click.style(f"[-] Critical Fault: Could not find 'dashboard.py' at target location: {dashboard_path}", fg="red"))
        return

    try:
        click.echo(click.style("[*] Spawning live telemetry monitoring web app instance...", fg="cyan"))
        subprocess.run(["streamlit", "run", dashboard_path], check=True)
    except KeyboardInterrupt:
        click.echo(click.style("\n[-] Visual matrix frame session terminated cleanly.", fg="green"))
    except Exception as e:
        click.echo(click.style(f"[-] Execution Interruption: Streamlit failed to spin up. Details: {e}", fg="red"))

if __name__ == "__main__":
    main()
