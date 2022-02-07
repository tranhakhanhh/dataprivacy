import math
import random
import time
import matplotlib.pyplot as plt
import numpy
from phe import paillier

MAX_INTEGER = 1000
FIELD_SIZE = 35452590104031691935943


def generate_n_values(n):
    """
    This function takes in n and return a list of integers of size n
    :param n: size of the returned list
    :return: a list of integers of size n
    """
    secrets = [random.randint(0, MAX_INTEGER) for _ in range(n)] # pick the integers' values randomly
    return secrets


def no_privacy(n, secrets):
    """
    This function calculates the average of list secrets
    :param n: the size of the list secrets
    :param secrets: a list of integers
    :return: the average value of the list
    """
    return sum(secrets)/n


def paillier_encryption(n, secrets):
    """
    This function calculates the average of list secrets using the paillier encryption approach
    :param n: the size of list secrets
    :param secrets: a list of integers
    :return: the average value of the list
    """
    # set up
    public_key, private_key = paillier.generate_paillier_keypair()

    # encrypt
    encrypted_secrets = [public_key.encrypt(num) for num in secrets]

    # decrypt
    encrypted_sum = sum(encrypted_secrets)
    avg = private_key.decrypt(encrypted_sum)/n
    return avg


def generate_coeff(t, secret):
    """
    This function creates a list of random coefficients for a polynomial f of degree t where f(0) = secret
    :param t: the degree of the polynomial
    :param secret: the value coefficient of x^0 needs to be set to
    :return: a list of coefficients
    """
    coeff = [random.randint(0, FIELD_SIZE-1) for i in range(t - 1)] # pick random values for the first t-1 coefficients
    coeff.append(secret) # set the last coefficient to be equal to secret
    return coeff


def poly(x, coeff):
    """
    This function calculates the value of polynomial f with coefficients corresponding to coeff at point x
    :param x: point at which we want to calculate f
    :param coeff: a list of coefficients
    :return: value of f at point x, so f(x)
    """
    f_x = 0
    k = len(coeff)
    for i in range(k):
        f_x += (coeff[i] * pow(x, k-i-1)) % FIELD_SIZE
    return f_x % FIELD_SIZE


def generate_shares(n, k, secrets):
    """
    This function distribute integers in secrets to n people using Shamir secret approach
    At least k people's shares are needed to reconstruct the original sum of all integers in secrets
    :param n: the number of secrets & the number of people
    :param k: the number of people needed to reconstruct the secrets
    :param secrets: list of integer of size n
    :return: a list of list of each person's index and shares of each secret
    """
    # a list of list where each small list is a person's share
    shares = [[i+1] for i in range(n)] # the first item in each small list is the person's index
    for secret in secrets:
        coeff = generate_coeff(k, secret)

        for i in range(n):
            f_i = poly(i+1, coeff)
            shares[i].append(f_i)
    return shares


def reconstruct_secret(shares):
    """
    This function uses Shamir secret approach to reconstruct the original sum of all integers in secrets
    :param shares: a list of list of each person's index and shares of each secret
    :return: the calculated sum of all numbers in secrets
    """
    result = 0

    for share_i in shares: # go through each person's shares
        i = share_i[0] # record the index of the person
        f_i = 0
        for x in range(1, len(share_i)): # take the sum of a person's n shares
            f_i += share_i[x]

        f_i = f_i % FIELD_SIZE
        l_i = 1

        for share_j in shares: # calculate l_i
            j = share_j[0]
            if j != i:
                l_i *= -j*pow(i-j, -1, FIELD_SIZE)

        result += (l_i * f_i) % FIELD_SIZE

    return result % FIELD_SIZE


def shamir_secret(n, secrets):
    """
    This function uses the Shamir secret approach to calculate the average of all values in secrets
    :param n: size of secrets
    :param secrets: a list of integers
    :return: the sum calculated using the Shamir secret approach
    """
    t = math.floor(n / 2) # the number of untrusted people

    # Distribute shares to n people where at least t+1 people are needed to reconstruct the sum of secrets
    shares = generate_shares(n, t+1, secrets)

    # Randomly pick t+1 people's shares from the list of n people's shares
    chosen_shares = random.sample(shares, t+1)
    # Use t+1 people's shares to reconstruct the sum of secrets
    avg = reconstruct_secret(chosen_shares)/n
    return avg


def differential_privacy(n, secrets):
    """
    This function calculates the average of all values in secrets using a differential privacy mechanism
    :param n: the size of list secrets
    :param secrets: a list of integers
    :return: the calculated average
    """
    # our given privacy budget
    theta = 1.0

    # s_q = maximum impact one row can have on the sum = MAX_INTEGER
    noise = numpy.random.laplace(loc=0, scale=MAX_INTEGER/theta)
    return (sum(secrets)+noise)/n


def run_10_times(n, secrets, approach, approach_index, ori_avg):
    """
    This function calculates the average of secrets 10 times using a given approach and return the average runtime and
    accuracy.
    :param n: size of list secrets
    :param secrets: a list of integers
    :param approach: a list of privacy approaches
    :param approach_index: the index of the privacy approach in the list approach that will be used to calculate average
    :param ori_avg: the original average
    :return: the average runtime of the calculations and the average distance between the calculated average
    and the original average
    """
    runtime = []
    distance = []
    for i in range(10):
        start_time = time.time()
        avg = approach[approach_index](n, secrets)
        runtime.append(time.time() - start_time)
        distance.append(abs(ori_avg-avg))
    avg_runtime = sum(runtime)/10
    avg_distance = sum(distance)/10
    return avg_runtime, avg_distance


def generate_plot(values_of_n, data_list, fig_name):
    """
    This function plots a line graph and output the figure to a file named fig_name
    :param values_of_n: the values for x axis
    :param data_list: the values for y axis
    :param fig_name: the outputed file name
    :return: None
    """
    plt.clf()
    plt.plot(values_of_n, data_list[0], label="No privacy", marker='o')
    plt.plot(values_of_n, data_list[1], label="Paillier encryption", marker='s')
    plt.plot(values_of_n, data_list[2], label="Shamir secret", marker='d')
    plt.plot(values_of_n, data_list[3], label="Differential privacy", marker='^')
    plt.xlabel('Number of integers (n)')
    if fig_name == "runtime":
        plt.ylabel('Run-time (seconds)')
        plt.title('Run-time analysis of')
    else:
        plt.ylabel('Distance from the original average')
        plt.title('Accuracy analysis')
    plt.legend()
    plt.savefig(fig_name)


def main():
    values_of_n = [10, 50, 150, 300, 500]
    approach = [no_privacy, paillier_encryption, shamir_secret, differential_privacy]

    # These list keep track of the runtime and accuracy of each approach to be used for the plot later
    runtime = [[] for a in range(len(approach))]
    distance = [[] for a in range(len(approach))]

    for n in values_of_n:
        secrets = generate_n_values(n)
        ori_avg = sum(secrets)/n
        for a in range(len(approach)):
            avg_runtime, avg_distance = run_10_times(n, secrets, approach, a, ori_avg)
            runtime[a].append(avg_runtime)
            distance[a].append(avg_distance)
    generate_plot(values_of_n, runtime, "runtime")
    generate_plot(values_of_n, distance, "accuracy")


main()