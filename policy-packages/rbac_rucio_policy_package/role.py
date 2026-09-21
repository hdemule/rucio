roles = [
    {
        "name": "admin",
        "description": "Admin role with full access to all resources.",
        "permissions": [
            {
                "scope": "*",
                "action": "rw",
            },
        ],
    },
    {
        "name": "data-scientist",
        "description": "Data scientist role with read access to data scope and archived content.",
        "permissions": [
            {
                "scope": "data",
                "action": "r-",
            },
            {
                "scope": "archive*",
                "action": "r-",
            },
            {
                "scope": "atlas",
                "action": "rw",
            }
        ],
    },
]
