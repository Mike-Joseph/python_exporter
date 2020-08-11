# NOT MAINTAINED

Note that this is a project that was developed internally at The Mode Group
and has now been released under the Apache-2.0 license (see LICENSE and
NOTICE).  The Mode Group is not actively maintaining this project and is not
currently accepting pull requests, bug reports, or changes.  Users of this
project are welcome to fork it under the allowable terms of its license and
continue the project at their own discretion.

# python_exporter

Python Exporter for Prometheus.  Allows shell commands to be parsed and
exported for metric collection.

## Example Execution

```./python_exporter.py data/elasticache_omem.yaml```

### Example Result

```
# HELP redis_omem omemmetric
# TYPE redis_omem gauge
redis_omem{addr=10.0.1.137:48584,cmd=publish,env=beta,host=beta-push.cotalp.0001.usw1.cache.amazonaws.com,id=10115,service=elasticache} 0
# HELP redis_omem omemmetric
# TYPE redis_omem gauge
redis_omem{addr=10.0.2.17:58154,cmd=publish,env=beta,host=beta-push.cotalp.0001.usw1.cache.amazonaws.com,id=4945,service=elasticache} 0
# HELP redis_omem omemmetric
# TYPE redis_omem gauge
redis_omem{addr=10.0.1.137:36896,cmd=publish,env=beta,host=beta-push.cotalp.0001.usw1.cache.amazonaws.com,id=10112,service=elasticache} 0
# HELP redis_omem omemmetric
# TYPE redis_omem gauge
redis_omem{addr=10.0.1.137:36898,cmd=subscribe,env=beta,host=beta-push.cotalp.0001.usw1.cache.amazonaws.com,id=10113,service=elasticache} 0
# HELP redis_omem omemmetric
# TYPE redis_omem gauge
redis_omem{addr=10.0.1.137:48610,cmd=subscribe,env=beta,host=beta-push.cotalp.0001.usw1.cache.amazonaws.com,id=10114,service=elasticache} 0
# HELP redis_omem omemmetric
# TYPE redis_omem gauge
redis_omem{addr=10.0.1.233:58050,cmd=publish,env=beta,host=beta-push.cotalp.0001.usw1.cache.amazonaws.com,id=3025,service=elasticache} 0
# HELP redis_omem omemmetric
# TYPE redis_omem gauge
redis_omem{addr=10.0.0.49:58954,cmd=client,env=beta,host=beta-push.cotalp.0001.usw1.cache.amazonaws.com,id=10195,service=elasticache} 0
```
