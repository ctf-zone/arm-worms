#!/usr/bin/env python3

import random

import networkx as nx


class Graph():
    def __init__(self):
        self.graph = None
        self.x86 = []
        self.arm = []
        self.super = []
        self.ids = {}
        self.neighbors = {}

    def get_neighbors(self):
        for node in self.graph.nodes:
            neighbors = []
            for nodes in self.graph.edges:
                if node == nodes[0]:
                    neighbors.append(nodes[1])
                if node == nodes[1]:
                    neighbors.append(nodes[0])
            self.neighbors[self.ids[node]] = neighbors

    def get_rand_ids(self):
        for node in self.graph.nodes:
            while (True):
                random.seed()
                rand_id = random.randint(0x0000, 0x7fff)
                if not rand_id in list(self.ids.values()):
                    self.ids[node] = rand_id
                    break

    def init_rand(self):
        self.get_graph()
        self.get_clasters()
        self.get_rand_ids()
        self.get_neighbors()


class Grid(Graph):
    def __init__(self, num=11):
        self.num = num
        super(Grid, self).__init__()

    def get_graph(self):
        grid = nx.grid_graph([self.num] * 2)
        self.graph = grid

    def get_clasters(self):
        for node in self.graph.nodes:
            if (node[0] == self.num // 2) and (node[1] == self.num // 2):
                self.super.append(node)
                continue
            if not node[0] or not node[1]:
                self.x86.append(node)
                continue
            if (node[0] == (self.num - 1)) or (node[1] == self.num - 1):
                self.x86.append(node)
                continue
            self.arm.append(node)

    def get_ids(self):
        node_id = 0
        for node in self.graph.nodes:
            self.ids[node] = node_id
            node_id += 1

    def init(self):
        self.get_graph()
        self.get_clasters()
        self.get_ids()
        self.get_neighbors()


class Tree(Graph):
    def __init__(self, r=3, h=4):
        self.r = r
        self.h = h
        super(Tree, self).__init__()

    def get_graph(self):
        tree = nx.balanced_tree(self.r, self.h)
        self.graph = tree

    def get_clasters(self):
        edges = list(self.graph.edges)
        nodes = list(self.graph.nodes)
        for node in nodes:
            neighbours_num = 0
            for edge in edges:
                if (node == edge[0]) or (node == edge[1]):
                    neighbours_num += 1
            if neighbours_num == 1:
                self.x86.append(node)
                continue
            if neighbours_num == 3:
                self.super.append(node)
                continue
            self.arm.append(node)

    def get_ids(self):
        self.ids = {node: node for node in self.graph.nodes}

    def init(self):
        self.get_graph()
        self.get_clasters()
        self.get_ids()
        self.get_neighbors()


def test_grid():
    graph = Grid(11)
    graph.init()
    print('[x86]\n{}'.format(graph.x86))
    print('[arm]\n{}'.format(graph.arm))
    print('[super]\n{}'.format(graph.super))
    print('[ids]\n{}'.format(graph.ids))
    print('[neighbors]\n{}'.format(graph.neighbors))


def test_tree():
    graph = Tree(3, 4)
    graph.init()
    print('[x86]\n{}'.format(graph.x86))
    print('[arm]\n{}'.format(graph.arm))
    print('[super]\n{}'.format(graph.super))
    print('[ids]\n{}'.format(graph.ids))
    print('[neighbors]\n{}'.format(graph.neighbors))


if __name__ == '__main__':
    test_grid()
    test_tree()
