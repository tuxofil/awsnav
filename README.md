# AWS ECS Navigator

## Disclaimer

This tool is a perversion. Under normal circumstances you
should use AWS Management Console instead.

## Summary

If you don't have AWS Management Console access requisites
and have only AWS API key pairs, you can use this tool to
save some time obtaining information about your running
ECS clusters, containers, EC2 instances etc.

## License

[FreeBSD License](http://www.freebsd.org/copyright/freebsd-license.html).
You can obtain the license online or in the file LICENSE on
the top of Echessd source tree.

## Dependencies

* AWS CLI tool. `aws` executable must be installed in one of
 directories listed in the `PATH` environment variable;
* Python 2.x (tested only on 2.7).

## Configuration

Required environment variables:

* `AWS_DEFAULT_REGION`;
* `AWS_ACCESS_KEY_ID`;
* `AWS_SECRET_ACCESS_KEY`.

or you can define only `AWS_PROFILE` environment variable, if you
have corresponding sections in `~/.aws/config` and `~/.aws/credentials`.

## Usage

To see available command line options ans switches, do:

```
./awsnav.py -h
```

The tool acts like a HTTP server. Start it with:

```
./awsnav.py
```

Then point your browser to `http://127.0.0.1:9000/`. If access
requisites is OK, then you will see list of configured ECS clusters.
