import click


@click.group()
def cli_group():
    pass


@cli_group.command()
def register():
    print("Register!")


@cli_group.command()
def ask():
    print("Ask!")


if __name__ == '__main__':
    cli_group()