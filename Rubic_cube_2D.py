# rubiks_cube.py
import pygame
import sys
import random

# -------- Cube representation ----------
# Each face: 3x3 list of colors (single-letter strings)
# Faces: U (up), D (down), L (left), R (right), F (front), B (back)
# Colors: W (white) U, Y (yellow) D, O (orange) L, R (red) R, G (green) F, B (blue) B

FACE_ORDER = ['U', 'L', 'F', 'R', 'B', 'D']
STARTING_COLORS = {'U': 'W', 'D': 'Y', 'L': 'O', 'R': 'R', 'F': 'G', 'B': 'B'}

# color map for pygame
COLOR_MAP = {
    'W': (255, 255, 255),
    'Y': (255, 255, 0),
    'O': (255, 165, 0),
    'R': (200, 0, 0),
    'G': (0, 180, 0),
    'B': (0, 0, 200),
    'X': (30, 30, 30)  # fallback / border
}


def make_solved_cube():
    cube = {}
    for f in STARTING_COLORS:
        cube[f] = [[STARTING_COLORS[f] for _ in range(3)] for _ in range(3)]
    return cube


# rotate a 3x3 matrix clockwise or counterclockwise
def rotate_face_matrix(face_mat, clockwise=True):
    # clockwise rotation of 3x3
    if clockwise:
        return [list(reversed(col)) for col in zip(*face_mat)]
    else:
        # counterclockwise
        return [list(col) for col in zip(*reversed(face_mat))][::-1]


# helper: get row or column
def get_row(face, idx):
    return face[idx][:]


def set_row(face, idx, values):
    face[idx] = values[:]


def get_col(face, idx):
    return [face[r][idx] for r in range(3)]


def set_col(face, idx, values):
    for r in range(3):
        face[r][idx] = values[r]


# Implement face rotations updating adjacent faces.
# The mapping below is defined in standard cube orientation.
def rotate_cube_face(cube, face_name, clockwise=True):
    # first rotate the face itself
    cube[face_name] = rotate_face_matrix(cube[face_name], clockwise)

    # now move edge stickers among adjacent faces
    # For each face, define the four affected faces and which rows/cols are involved,
    # in order so they rotate cyclically when the face rotates clockwise.
    # Each entry is (adj_face, 'row'/'col', index, reverse_flag)
    # reverse_flag indicates whether to reverse the sequence when moving.

    if face_name == 'U':
        seq = [
            ('B', 'row', 0, False),
            ('R', 'row', 0, False),
            ('F', 'row', 0, False),
            ('L', 'row', 0, False)
        ]
    elif face_name == 'D':
        seq = [
            ('F', 'row', 2, False),
            ('R', 'row', 2, False),
            ('B', 'row', 2, False),
            ('L', 'row', 2, False)
        ]
    elif face_name == 'F':
        seq = [
            ('U', 'row', 2, False),
            ('R', 'col', 0, True),  # note orientation flips
            ('D', 'row', 0, True),
            ('L', 'col', 2, False)
        ]
    elif face_name == 'B':
        seq = [
            ('U', 'row', 0, True),
            ('L', 'col', 0, True),
            ('D', 'row', 2, False),
            ('R', 'col', 2, False)
        ]
    elif face_name == 'L':
        seq = [
            ('U', 'col', 0, False),
            ('F', 'col', 0, False),
            ('D', 'col', 0, False),
            ('B', 'col', 2, True)
        ]
    elif face_name == 'R':
        seq = [
            ('U', 'col', 2, False),
            ('B', 'col', 0, True),
            ('D', 'col', 2, False),
            ('F', 'col', 2, False)
        ]
    else:
        return  # unknown face

    # Read current sequences
    parts = []
    for (af, typ, idx, rev) in seq:
        if typ == 'row':
            p = get_row(cube[af], idx)
        else:
            p = get_col(cube[af], idx)
        parts.append(list(reversed(p)) if rev else p[:])

    # rotate them: if clockwise, shift right by 1; else shift left by 1
    if clockwise:
        parts = [parts[-1]] + parts[:-1]
    else:
        parts = parts[1:] + [parts[0]]

    # write back
    for (af, typ, idx, rev), data in zip(seq, parts):
        out = list(reversed(data)) if rev else data[:]
        if typ == 'row':
            set_row(cube[af], idx, out)
        else:
            set_col(cube[af], idx, out)


# ---------- Pygame UI ----------
CELL = 40
PADDING = 10
MARGIN = 20

# layout for the 2D net (row, col) for each face, measured in cells
NET_POS = {
    'U': (0, 1),
    'L': (1, 0),
    'F': (1, 1),
    'R': (1, 2),
    'B': (1, 3),
    'D': (2, 1)
}


def draw_cube_net(screen, cube, top_left):
    tx, ty = top_left
    for face, (nr, nc) in NET_POS.items():
        fx = tx + nc * (CELL * 3 + PADDING)
        fy = ty + nr * (CELL * 3 + PADDING)
        # draw 3x3 squares
        for r in range(3):
            for c in range(3):
                color_char = cube[face][r][c]
                color = COLOR_MAP.get(color_char, COLOR_MAP['X'])
                rect = pygame.Rect(fx + c * CELL, fy + r * CELL, CELL - 1, CELL - 1)
                pygame.draw.rect(screen, color, rect)
        # draw face border
        border_rect = pygame.Rect(fx, fy, 3 * CELL - 1, 3 * CELL - 1)
        pygame.draw.rect(screen, (20, 20, 20), border_rect, 2)


def scramble_cube(cube, moves=25):
    faces = ['U', 'D', 'L', 'R', 'F', 'B']
    for _ in range(moves):
        f = random.choice(faces)
        cw = random.choice([True, False])
        rotate_cube_face(cube, f, clockwise=cw)


def is_solved(cube):
    for f in cube:
        col = cube[f][0][0]
        for r in range(3):
            for c in range(3):
                if cube[f][r][c] != col:
                    return False
    return True


def main():
    pygame.init()
    screen_w = 800
    screen_h = 420
    screen = pygame.display.set_mode((screen_w, screen_h))
    pygame.display.set_caption("Rubik's Cube (2D net) — Controls shown below")
    font = pygame.font.SysFont(None, 20)
    bigfont = pygame.font.SysFont(None, 32)

    cube = make_solved_cube()

    # instructions text
    instructions = [
        "Controls:",
        " U / u : Up face clockwise / counterclockwise",
        " D / d : Down face clockwise / counterclockwise",
        " L / l : Left face cw / ccw",
        " R / r : Right face cw / ccw",
        " F / f : Front face cw / ccw",
        " B / b : Back face cw / ccw",
        " S : Scramble (25 random moves)",
        " C : Check solved",
        " Space : Reset to solved",
        " Esc or Q : Quit"
    ]

    clock = pygame.time.Clock()
    running = True
    message = "Welcome! Press S to scramble."

    while running:
        screen.fill((200, 200, 200))
        # draw net
        net_top_left = (MARGIN, MARGIN)
        draw_cube_net(screen, cube, net_top_left)

        # draw instructions
        x0 = 3 * (CELL * 3 + PADDING) + MARGIN + 20
        y0 = MARGIN
        for i, line in enumerate(instructions):
            txt = font.render(line, True, (30, 30, 30))
            screen.blit(txt, (x0, y0 + i * 22))

        # draw message
        msg_surf = bigfont.render(message, True, (10, 10, 10))
        screen.blit(msg_surf, (MARGIN, screen_h - 40))

        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                running = False
            elif event.type == pygame.KEYDOWN:
                ch = event.unicode
                # allow uppercase detection via shift: event.unicode respects case
                if ch in ('U', 'u'):
                    rotate_cube_face(cube, 'U', clockwise=(ch == 'U'))
                    message = f"Rotated U {'CW' if ch == 'U' else 'CCW'}"
                elif ch in ('D', 'd'):
                    rotate_cube_face(cube, 'D', clockwise=(ch == 'D'))
                    message = f"Rotated D {'CW' if ch == 'D' else 'CCW'}"
                elif ch in ('L', 'l'):
                    rotate_cube_face(cube, 'L', clockwise=(ch == 'L'))
                    message = f"Rotated L {'CW' if ch == 'L' else 'CCW'}"
                elif ch in ('R', 'r'):
                    rotate_cube_face(cube, 'R', clockwise=(ch == 'R'))
                    message = f"Rotated R {'CW' if ch == 'R' else 'CCW'}"
                elif ch in ('F', 'f'):
                    rotate_cube_face(cube, 'F', clockwise=(ch == 'F'))
                    message = f"Rotated F {'CW' if ch == 'F' else 'CCW'}"
                elif ch in ('B', 'b'):
                    rotate_cube_face(cube, 'B', clockwise=(ch == 'B'))
                    message = f"Rotated B {'CW' if ch == 'B' else 'CCW'}"
                else:
                    key = event.key
                    if key == pygame.K_s:
                        scramble_cube(cube, moves=25)
                        message = "Scrambled"
                    elif key == pygame.K_SPACE:
                        cube = make_solved_cube()
                        message = "Reset to solved"
                    elif key == pygame.K_c:
                        message = "Solved!" if is_solved(cube) else "Not solved yet."
                    elif key in (pygame.K_ESCAPE, pygame.K_q):
                        running = False

        pygame.display.flip()
        clock.tick(30)

    pygame.quit()
    sys.exit()


if __name__ == "__main__":
    main()
