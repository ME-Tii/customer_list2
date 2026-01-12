import random
import os
import time

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def render_board(board, snake, food):
    b = [row[:] for row in board]
    for x, y in snake:
        if [x, y] == snake[0]:
            b[y][x] = '🐍'
        else:
            b[y][x] = '🟢'
    fx, fy = food
    b[fy][fx] = '🍎'
    return '\n'.join(''.join(row) for row in b)

def main():
    width, height = 20, 20
    board = [['.' for _ in range(width)] for _ in range(height)]
    snake = [[width//2, height//2]]
    direction = 'right'
    food = [random.randint(0, width-1), random.randint(0, height-1)]
    score = 0
    game_over = False

    print("Snake Game! Use WASD to move, Q to quit.")
    print("Press Enter to start.")
    input()

    while not game_over:
        clear_screen()
        print(f"Score: {score}")
        print(render_board(board, snake, food))

        # Get input
        import sys
        import select
        if select.select([sys.stdin], [], [], 0.1)[0]:
            move = sys.stdin.read(1).lower()
        else:
            move = None

        if move == 'q':
            break

        new_dir = None
        if move == 'w':
            new_dir = 'up'
        elif move == 's':
            new_dir = 'down'
        elif move == 'a':
            new_dir = 'left'
        elif move == 'd':
            new_dir = 'right'

        if new_dir:
            opposites = {'up':'down', 'down':'up', 'left':'right', 'right':'left'}
            if new_dir != opposites.get(direction):
                direction = new_dir

        # Move snake
        head = snake[0].copy()
        if direction == 'up':
            head[1] -= 1
        elif direction == 'down':
            head[1] += 1
        elif direction == 'left':
            head[0] -= 1
        elif direction == 'right':
            head[0] += 1

        # Check walls
        if head[0] < 0 or head[0] >= width or head[1] < 0 or head[1] >= height:
            game_over = True
            print("Game Over! Hit wall.")
        # Check self
        elif head in snake:
            game_over = True
            print("Game Over! Hit self.")
        else:
            snake.insert(0, head)
            if head == food:
                score += 1
                food = [random.randint(0, width-1), random.randint(0, height-1)]
                while food in snake:
                    food = [random.randint(0, width-1), random.randint(0, height-1)]
            else:
                snake.pop()

        time.sleep(0.2)  # Speed

    print(f"Final Score: {score}")

if __name__ == '__main__':
    main()