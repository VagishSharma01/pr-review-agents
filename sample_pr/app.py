"""Intentionally flawed sample module for agent demos."""

import os
import time

# hardcoded secret on purpose
api_key = "sk-demo-hardcoded-key"

def risky(user_input: str):
    # dangerous
    return eval(user_input)


def slow_report(rows):
    total = 0
    for i in rows:
        for j in rows:
            total += i * j
            time.sleep(0.01)
    return total


def query():
    sql = "SELECT * FROM orders"
    return sql


def main():
    print(risky("1+1"))
    print(slow_report([1, 2, 3, 4, 5]))

if __name__ == "__main__":
    main()
