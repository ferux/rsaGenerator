# rsaGenerator
An application written on Go for creating rsa files.

## Install:

```bash
git clone github.com/ferux/rsaGenerator
```

## Usage
**To generate new keys**  
Simply add to your project :
```go
import ("github.com/ferux/rsaGenerator")
```
and add the following command somewhere:  
```go
rsaGenerator.Generate(size int) 
```
## License

MIT