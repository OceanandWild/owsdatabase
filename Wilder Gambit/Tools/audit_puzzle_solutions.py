"""Comprueba con el Stockfish del proyecto que las soluciones de los puzzles sean legales
y que sean la mejor jugada de la posición.

Revisa las dos listas del juego:
  · Assets/_Project/Scripts/Core/PuzzleManager.cs   (entrenamiento, 30)
  · Assets/_Project/Scripts/Core/DailyChallenge.cs  (reto diario, 12)

Dos comprobaciones por puzzle:
  1. Toda la línea guionada se puede jugar (ply a ply, con el FEN que devuelve el
     motor después de cada jugada). Una jugada ilegal no avanza la posición, así que
     el FEN se repite: eso delata al guion que mueve piezas atravesando lo que hay
     por medio (la dama que "escapa" de un fork pasando por encima del caballo) o
     que se juega fuera de turno.
  2. La primera jugada coincide con la mejor del motor.

Uso: python Tools/audit_puzzle_solutions.py [profundidad]
     Con profundidad 0 solo se revisa la legalidad (rápido, sin análisis).
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
ENGINE = os.path.join(PROJECT, "Assets", "StreamingAssets", "Stockfish", "stockfish.exe")
PM = os.path.join(PROJECT, "Assets", "_Project", "Scripts", "Core", "PuzzleManager.cs")
DC = os.path.join(PROJECT, "Assets", "_Project", "Scripts", "Core", "DailyChallenge.cs")
DEPTH = int(sys.argv[1]) if len(sys.argv) > 1 else 14


class Engine:
    def __init__(self, path):
        self.proc = subprocess.Popen([path], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self.send("uci")
        self.wait("uciok")
        self.send("setoption name Threads value 1")
        self.send("setoption name MultiPV value 4")
        self.send("isready")
        self.wait("readyok")

    def send(self, cmd):
        self.proc.stdin.write(cmd + "\n")
        self.proc.stdin.flush()

    def wait(self, token, limit=6000):
        lines = []
        for _ in range(limit):
            line = self.proc.stdout.readline()
            if not line:
                break
            line = line.strip()
            lines.append(line)
            if line.startswith(token):
                break
        return lines

    def board_fen(self, fen, moves):
        """FEN que devuelve el motor tras aplicar `moves` (el comando `d`)."""
        cmd = "position fen " + fen + ((" moves " + " ".join(moves)) if moves else "")
        self.send(cmd)
        self.send("d")
        lines = self.wait("Checkers")
        for line in lines:
            if line.startswith("Fen:"):
                return line.split("Fen:", 1)[1].strip()
        return None

    def illegal_plies(self, fen, moves):
        """[(ply, jugada)] de las jugadas del guion que no se pueden jugar.

        Si el motor rechaza una jugada se queda en la posición anterior, así que la
        comparación entre FENs consecutivos lo detecta sin depender de los mensajes.
        """
        malas = []
        previo = self.board_fen(fen, [])
        for i, mv in enumerate(moves, start=1):
            actual = self.board_fen(fen, moves[:i])
            if actual is None or actual == previo:
                malas.append((i, mv))
            previo = actual
        return malas

    def analyse(self, fen):
        self.send("position fen " + fen)
        self.send(f"go depth {DEPTH}")
        lines = self.wait("bestmove")
        best = next((l.split()[1] for l in lines if l.startswith("bestmove")), None)
        moves = []
        for l in lines:
            m = re.search(r"multipv (\d+).*? pv ([a-h][1-8][a-h][1-8][qrbn]?)", l)
            if m and m.group(2) not in moves:
                moves.append(m.group(2))

        # La nota buena es la del último análisis de la PV principal: la primera línea
        # "info" que llega es la de profundidad 1 y no dice nada de la posición.
        principal = None
        for l in lines:
            if l.startswith("info depth") and ("multipv 1" in l or " multipv " not in l):
                principal = l

        mate = cp = None
        if principal:
            m = re.search(r"score mate (-?\d+)", principal)
            if m:
                mate = int(m.group(1))
            else:
                m = re.search(r"score cp (-?\d+)", principal)
                if m:
                    cp = int(m.group(1))
        return best, moves, mate, cp


def parse_training():
    src = open(PM, encoding="utf-8").read()
    out = []
    for m in re.finditer(r'id = "([^"]+)".*?fen = "([^"]+)"(?:.|\n)*?solutionMoves = new\[\] \{([^}]*)\}', src):
        moves = re.findall(r'"([a-h][1-8][a-h][1-8][qrbn]?)"', m.group(3))
        out.append((m.group(1), m.group(2), moves))
    return out


def parse_daily():
    src = open(DC, encoding="utf-8").read()
    fens = re.findall(r'"([^"]*\/[^"]*\/[^"]*\/[^"]*\/[^"]*\/[^"]*\/[^"]*\/[^"]*) (?:w|b) ', src)
    # los 10 FEN y las 10 soluciones están en dos arrays consecutivos
    block_f = re.search(r"dailyFens = new\[\]\s*\{(.*?)\};", src, re.S).group(1)
    block_s = re.search(r"dailySolutions = new\[\]\s*\{(.*?)\};", src, re.S).group(1)
    fens = re.findall(r'"([^"]+)"', block_f)
    sols = re.findall(r'"([^"]+)"', block_s)
    return [(f"daily{i}", fens[i], [sols[i]]) for i in range(min(len(fens), len(sols)))]


def main():
    if not os.path.exists(ENGINE):
        print(f"no encuentro el motor en {ENGINE}")
        return 1

    eng = Engine(ENGINE)
    puzzles = parse_training() + parse_daily()
    modo = "solo legalidad" if DEPTH <= 0 else f"legalidad + mejor jugada (depth {DEPTH})"
    print(f"{len(puzzles)} puzzles · {modo}\n")

    lineas_malas = 0
    jugadas_malas = 0
    sin_solucion = 0
    no_mejores = 0

    for pid, fen, sols in puzzles:
        if not sols:
            print(f"{pid:12s} SIN SOLUCIÓN")
            sin_solucion += 1
            continue

        ilegales = eng.illegal_plies(fen, sols)
        if ilegales:
            lineas_malas += 1
            jugadas_malas += len(ilegales)
            detalle = ", ".join(f"ply {i} ({mv})" for i, mv in ilegales)
            print(f"{pid:12s} LÍNEA ILEGAL -> {detalle}")
            continue

        if DEPTH <= 0:
            print(f"{pid:12s} {len(sols)} jugada(s) · todas legales")
            continue

        best, top, mate, cp = eng.analyse(fen)
        first = sols[0]
        tag = "ok" if best == first else "REVISAR"
        if best != first:
            no_mejores += 1
        extra = ""
        if mate is not None:
            extra = f" mate en {abs(mate)}"
        elif cp is not None:
            extra = f" eval {cp/100:+.2f}"
        print(f"{pid:12s} solución {first:6s} motor {str(best):6s} {tag}{extra}")
        if best != first:
            print(f"             mejores: {top[:4]}")

    print(f"\nlíneas ilegales: {lineas_malas} · jugadas ilegales: {jugadas_malas} · sin solución: {sin_solucion}")
    if DEPTH > 0:
        print(f"soluciones que no son la mejor jugada: {no_mejores}")
    return 1 if (lineas_malas or jugadas_malas or sin_solucion or no_mejores) else 0


if __name__ == "__main__":
    sys.exit(main())
