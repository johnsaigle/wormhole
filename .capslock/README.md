# Wormhole capslock

The file `capslock-node.json` contains the snapshot of the capabilities for `node/`.

## Commiting a new snapshot


```sh
cd node/
capslock -output=json > ../.capslock/capslock-node-snapshot.json
```

## Testing

To see what the tool's output looks like, run the following command from `node/`

```sh
# go install github.com/google/capslock/cmd/capslock@latest

# Run against example file to see what output looks like
capslock -output=compare ../.capslock/capslock-example.json

# Empty output means the snapshot is up to date
capslock -output=compare ../.capslock/capslock-node-snapshot.json
```
