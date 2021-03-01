import typer
import configparser

app = typer.Typer()

misp_app = typer.Typer()
app.add_typer(misp_app, name="misp")

# コンフィグファイルの読み込み
def read_config():
    filename = "metemctl.ini"
    config = configparser.ConfigParser()
    config.read(filename) 
    return config


@app.callback()
def app_callback(ctx: typer.Context):
    ctx.meta['config'] = read_config()

@app.command()
def new():
    typer.echo(f"new")

@app.command()
def catalog():
    typer.echo(f"catallog")

@app.command()
def misp():
    typer.echo(f"misp")

@misp_app.command("open")
def misp_open(ctx: typer.Context):
    try:
        misp_url = ctx.meta['config']['general']['misp_url']
        typer.echo(misp_url)
        typer.launch(misp_url)
    except KeyError as e:
        typer.echo(e, err=True)

@app.command()
def run():
    typer.echo(f"run")

@app.command()
def check():
    typer.echo(f"check")

@app.command()
def publish():
    typer.echo(f"publish")

@app.command()
def account():
    typer.echo(f"account")

@app.command()
def config():
    typer.echo(f"config")

@app.command()
def contract():
    typer.echo(f"contract")

@app.command()
def console():
    typer.echo(f"console")


if __name__ == "__main__":
    app()