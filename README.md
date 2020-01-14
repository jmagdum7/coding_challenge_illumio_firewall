# Illumio PCE Team Coding Challenge
> The project consists of a firewall that is able to pass inputs given a pre-determined set of rules.

## Table of contents
* [Language Used](#language-used)
* [Files Included](#files-included)
* [How to Run](#how-to-run)
* [Design Choices](#design-choices)
* [Further Improvement](#further-improvement)
* [Teams Interested In](#teams-interested-in)
* [Contact](#contact)

## Language Used

Python 3.6

## Files Included
1. firewall.py
  This file contains the main Firewall class that implements the functions for preprocessing the input, validating it and the accept_packet function which returns the final boolean value for the network
2. test_firewall.py
  This file details all the unit test cases for the firewall.py file. The methods from the firewall.py are imported and test cases are written for the methods. The sample test cases mentioned in the guide are also included in this file.
3. rules.csv
  The rules for which the input must conform to are included in this file.

## How to Run
1. Download both files on your laptop or computer and make sure they are on the same directory or folder
2. Open terminal on your laptop
3. Navigate to the directory which contains both the files on the terminal
4. Type the following command:
`$ python test_firewall.py`
5. To add more test cases, edit the test_firewall.py file

## Design Choices
1. I have chosen to approach a general strategy to parse the input for now.
2. I instead focused on simplifying the need for checking the test cases

## Further Improvement
Given more time:
1. I would like to use better data structures to better store the set of rules.
2. I would make optimizations to match multiple rules simultaneously.

## Teams Interested in
1. Policy Team
2. Data Team

## Contact
Created by [@jmagdum7](https://www.linkedin.com/in/junaidmagdum/)
