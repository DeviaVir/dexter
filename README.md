# dexter

[![Build Status](https://travis-ci.org/DeviaVir/dexter.svg?branch=master)](https://travis-ci.org/DeviaVir/dexter)

`dexter` is a OIDC (OpenId Connect) helper to create a hassle-free Kubernetes login experience powered by Google or Azure as Identity Provider.
All you need is a properly configured Google or Azure client ID & secret.

## Docker

Run in a container:
```
docker run -it -p 3000:3000 --rm -e CLIENT_ID=REDACTED -e CLIENT_SECRET=REDACTED -e KUBE_CONFIG_PATH=/kubeconfig -e USER=root -v kubeconfig:/kubeconfig deviavir/dexter
```

Users visiting `your-host:3000` will be oauth'ed and presented with a kubeconfig they can use to authenticate.

We expect `your-email` as the boilerplate email in the `kubeconfig` you provide. You can also simply not provide a kubeconfig if you only want the user authentication details returned.

## Authors

Initial code was written by [Daniel Kerwin](mailto:daniel@gini.net) & [David González Ruiz](mailto:david@gini.net)

## Acknowledgements

`dexter` was inspired by this [blog post series](https://thenewstack.io/tag/Kubernetes-SSO-series) by [Joel Speed](https://thenewstack.io/author/joel-speed/), [Micah Hausler's k8s-oidc-helper
](https://github.com/micahhausler/k8s-oidc-helper) & [CoreOS dex](https://github.com/coreos/dex).

## License

MIT License. See [License](/LICENSE) for full text.
