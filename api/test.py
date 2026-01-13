def handler(request):
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "text/html"},
        "body": "<h1>CipherGuard Works!</h1>"
    }
