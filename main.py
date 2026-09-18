import os
import sys
import click
import subprocess

CWD = os.getcwd()
possible_src_paths = [
    CWD,
    os.path.join(CWD, "pathasm", "src"),
    os.path.join(CWD, "src"),
    os.path.dirname(os.path.abspath(__file__)),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "pathasm", "src")
]

for path_target in possible_src_paths:
    if path_target not in sys.path:
        sys.path.insert(0, path_target)

@click.group()
def main():
    """🥷 PathAsm: Open-Source Attack Path Explorer & AD Telemetry Evasion Engine"""
    pass

@main.command()
@click.option('--dc', default=None, help='Target Domain Controller IP or FQDN')
@click.option('--user', default=None, help='User Distinguished Name (DN) or domain username')
@click.option('--password', default=None, help='Password for authentication')
@click.option('--output', default='infrastructure_dump.json', help='Output JSON metadata path')
def run(dc, user, password, output):
    """Execute active network data collection over the target Active Directory environment."""
    click.echo(click.style("[*] Initializing PathAsm Discovery Engine...", fg="cyan"))
    try:
        from collector import ActiveDirectoryCollector
        absolute_output = os.path.abspath(output)
        hound = ActiveDirectoryCollector(domain_controller=dc, user_dn=user, password=password)
        hound.run_discovery_cycle()
        hound.serialize_and_export(output_filename=absolute_output)
        click.echo(click.style(f"[+] Domain topology data compiled successfully!\n[+] Output saved to: {absolute_output}", fg="green"))
    except Exception as e:
        click.echo(click.style(f"[-] Operational Failure during collection cycle: {e}", fg="red"))

@main.command()
def view():
    """Launch the interactive graphical dashboard inside your default web browser."""
    click.echo(click.style("[*] Bootstrapping PathAsm Visual Matrix Frame...", fg="cyan"))
    
    dashboard_path = None
    for path_target in possible_src_paths:
        test_path = os.path.join(path_target, "dashboard.py")
        if os.path.exists(test_path):
            dashboard_path = test_path
            break
            
    if not dashboard_path or not os.path.exists(dashboard_path):
        click.echo(click.style("[-] Critical Fault: Could not locate 'dashboard.py' anywhere in your path topology.", fg="red"))
        return

    process = None
    try:
        click.echo(click.style("[*] Spawning live telemetry monitoring web app instance...", fg="cyan"))
        process = subprocess.Popen(["streamlit", "run", dashboard_path])
        process.wait()
    except (KeyboardInterrupt, SystemExit):
        click.echo(click.style("\n[*] Intercepted termination signal. Purging process threads...", fg="yellow"))
        if process:
            try:
                process.terminate()
                process.wait(timeout=2)
            except Exception:
                process.kill()
        click.echo(click.style("[+] Visual matrix frame session terminated cleanly.", fg="green"))
    except Exception as e:
        click.echo(click.style(f"[-] Execution Interruption: Streamlit failed to spin up. Details: {e}", fg="red"))
    finally:
        if os.path.exists("temp_graph.html"):
            try: os.remove("temp_graph.html")
            except Exception: pass

if __name__ == "__main__":
    main()
