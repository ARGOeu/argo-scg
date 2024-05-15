def namespace4tenant(tenant, namespaces):
    n4t = ""
    for namespace, tenants in namespaces.items():
        if tenant in tenants:
            n4t = namespace
            break

    return n4t
