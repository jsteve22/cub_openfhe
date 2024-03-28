# cub

This repository holds all of the C files for implementing a polynomial multiplication layer evaluation for conv2d layers in Gazelle. 
This will also hold a dockerfile to create an image to run this code. 

### Building
```
docker build -t cubimg .
docker run -it --name cub --mount "type=bind,source=$PWD,target=/home/" cubimg
```

To start the same container again use:
```
docker start -i cub
```

### Testing
Once in the docker container: 
```
cd bfv/
make
./zntt_cub
```