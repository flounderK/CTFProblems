#!/usr/bin/python3
import random
import time
import operator
import os
import argparse
import sys
__author__ = "Clifton Wolfe"


def div(a, b):
    """I need my values rounded"""
    return round(operator.truediv(a, b), 2)


def main(args):
    print("Here's the deal: You have 1000 math problems to solve, and very little "
          "time to do it in. For clarity, all division should be rounded to 2 "
          "decimal places, ^ is xor (not to-the-power-of)."
          " Also just for fun, some "
          "the inputs will be in hex, and all will be randomly generated. "
          "")
    problems = generate_problem_set(args.mean_mode)
    quiz(problems, args.time_limit)
    # if they get to this point, print the flag
    with open(args.flag_file, "r") as f:
        flag = f.read()
    print(flag)


def random_rep(a):
    """Determines whether the prompt shown to the user will be in hex"""
    c = random.randint(1, 15)
    if c in [4, 11, 13]:
        result = str(hex(a))
    else:
        result = str(a)
    return result


def generate_problem_set(mean_mode=True):
    operator_choices = [(operator.add, '+'), (operator.mul, '*'),
                        (operator.sub, '-'),
                        (div, '/'),
                        (operator.mod, '%')]

    mean_operator_choices = [(operator.and_, '&'), (operator.xor, '^'),
                             (operator.lshift, '<<'),
                             (operator.rshift, '>>'), (operator.or_, '|')]
    if mean_mode is True:
        operator_choices.extend(mean_operator_choices)

    problems = list()
    for problem_no in range(1000):
        func, rep = random.choice(operator_choices)
        a = random.randint(1, 100000)
        b = random.randint(1, 100000 if func not in [operator.rshift,
                                                     operator.lshift] else 20)
        answer = func(a, b)
        str_a = random_rep(a)
        str_b = random_rep(b)
        prompt = f"{str_a} {rep} {str_b} = ? : "
        problems.append((prompt, answer))

    return problems


def quiz(problems, time_limit):
    start = time.time()
    for prompt, answer in problems:
        response = ''
        while response == '':
            curtime = time.time()
            delta_t = round(curtime - start, 3)
            if delta_t > time_limit:
                print(f"Sorry, you took too long. Your time: {delta_t}")
                sys.exit(1)
            response = input(prompt)
        try:
            response = float(response)
        except:
            print(f"Error: Unable to represent {response} as an integer")
            sys.exit(1)

        if response == answer:
            print("correct")
        else:
            print(f"Nope, correct answer was {answer}")
            sys.exit(1)
        curtime = time.time()
        delta_t = round(curtime - start, 3)
        if delta_t > time_limit:
            print(f"Sorry, you took too long. Your time: {delta_t}")
            sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="This is a basic challenge meant to teach people the basics of using "
                                     "sockets for communication")
    parser.add_argument("--flag_file", type=str, help="The path to the "
                        "flag to print on success", default="flag.txt")
    parser.add_argument("-m", "--mean-mode", action="store_true", default=True,
                        help="This just adds a few extra operators for people to handle,"
                        " it isn't really that mean")
    parser.add_argument("-t", "--time-limit", type=int, default=45,
                        help="This is the time limit users will have to "
                             "enter in their responses. Increase if there is high server latency")
    args = parser.parse_args()
    if not os.path.isfile(args.flag_file):
        print("That isn't a valid flag file")
        sys.exit(1)
    main(args)


