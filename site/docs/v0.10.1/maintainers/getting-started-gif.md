To refresh the gif image included in [getting-started.md](/docs/getting-started.md), follow these
steps:

 * install [asciinema](https://asciinema.org/)
 * set `PS1="> "` in your bash profile file (e.g. `.bashrc`, `zshrc`, ...) to simplify the prompt
 * record the cast with the correct shell, e.g. `SHELL=zsh asciinema rec my.cast`
 * convert the cast file to a gif file: `docker run --rm -v $PWD:/data -w /data asciinema/asciicast2gif -s 3 -w 120 -h 20 my.cast my.gif`
 * upload the gif file to Github's CDN by following these
   [instructions](https://gist.github.com/vinkla/dca76249ba6b73c5dd66a4e986df4c8d)
 * update the link in [getting-started.md](/docs/getting-started.md) by opening
   a PR
