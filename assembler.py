import tkinter as tk
from tkinter import ttk, filedialog
from tkinter import scrolledtext

class MIC1Simulator:
    def __init__(self, root):
        self.root = root
        self.root.title("MIC-1 Simulator")
        self.style = ttk.Style()
        self.style.theme_use("clam")

        self.style.configure("TFrame", background="#00BBFA")
        self.style.configure("TLabelFrame", background="#001DFA", foreground="#FFFFFF", font=("Arial", 12, "bold"))
        self.style.configure("TLabel", background="#00BBFA", foreground="#FFFFFF", font=("Arial", 12))
        self.style.configure("TButton", background="#006CFA", foreground="#FFFFFF", font=("Arial", 12))
        self.style.map("TButton", background=[('active', '#539BFA')])

        self.main_frame = ttk.Frame(root, padding="10 10 10 10")
        self.main_frame.pack(fill="both", expand=True)

        #iniciando variaveis
        self.pc = '0000000000000000'
        self.ac = '0000000000000000'
        self.sp = '0000000000000000'
        self.memory = {}
        self.instruction_cache = []
        self.data_cache = {}

        self.variable_map = {}  #mapeando a memoria

        self.labels = {}
        self.is_running = False
        self.current_instruction_index = 0
        self.jneg_count = 0

        self.load_button = ttk.Button(self.main_frame, text="Load Program", command=self.load_program)
        self.load_button.grid(row=0, column=0, padx=5, pady=5)

        self.run_button = ttk.Button(self.main_frame, text="Run", command=self.run_simulation)
        self.run_button.grid(row=0, column=1, padx=5, pady=5)

        self.next_button = ttk.Button(self.main_frame, text="Next", command=self.step_simulation)
        self.next_button.grid(row=0, column=2, padx=5, pady=5)

        self.pc_label = ttk.Label(self.main_frame, text=f"PC (Program Counter): {self.pc}")
        self.pc_label.grid(row=1, column=0, columnspan=3, pady=5)

        self.ac_label = ttk.Label(self.main_frame, text=f"AC (Accumulator): {self.ac}")
        self.ac_label.grid(row=2, column=0, columnspan=3, pady=5)

        self.sp_label = ttk.Label(self.main_frame, text=f"SP (Stack Pointer): {self.sp}")
        self.sp_label.grid(row=3, column=0, columnspan=3, pady=5)

        self.create_shadowed_frame("Memory", 4, 10)
        self.create_shadowed_frame("Instruction Cache", 5, 6)
        self.create_shadowed_frame("Data Cache", 6, 6)

        self.instructions = {
            'LODD': '0000',
            'STOD': '0001',
            'ADDD': '0010',
            'SUBD': '0011',
            'JPOS': '0100',
            'JZER': '0101',
            'JNEG': '1100',
            'JUMP': '0110',
            'LOCO': '0111',
            'LODL': '1000',
            'STODL': '1001',
            'ADDL': '1010',
            'PUSHI': '1011',
            'POPI': '1101',
            'INSP': '1111'
        }

    def create_shadowed_frame(self, label, row, height):
        shadow_frame = tk.Frame(self.main_frame, background="#87ADE1")
        shadow_frame.grid(row=row, column=0, columnspan=3, pady=10, padx=10, sticky="nsew")

        label_frame = ttk.LabelFrame(shadow_frame, text=label, padding="10 10 10 10")
        label_frame.pack(fill="both", expand=True, padx=3, pady=3)

        if label == "Memory":
            self.memory_frame = label_frame
            self.memory_text = scrolledtext.ScrolledText(self.memory_frame, height=height, wrap=tk.WORD)
            self.memory_text.pack(fill="both", expand=True)
        elif label == "Instruction Cache":
            self.instruction_cache_frame = label_frame
            self.instruction_cache_text = scrolledtext.ScrolledText(self.instruction_cache_frame, height=height, wrap=tk.WORD)
            self.instruction_cache_text.pack(fill="both", expand=True)
        elif label == "Data Cache":
            self.data_cache_frame = label_frame
            self.data_cache_text = scrolledtext.ScrolledText(self.data_cache_frame, height=height, wrap=tk.WORD)
            self.data_cache_text.pack(fill="both", expand=True)

    def load_program(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, 'r') as file:
                program = file.readlines()
                self.memory_text.delete(1.0, tk.END)
                for line in program:
                    self.memory_text.insert(tk.END, line)
            self.assign_memory_addresses(program)
            self.populate_instruction_cache(program)
            self.update_memory_display()

    def run_simulation(self):
        if self.is_running:
            return
        self.is_running = True
        self.current_instruction_index = 0
        self.jneg_count = 0
        self.step_simulation()

    def step_simulation(self):
        if not self.is_running or self.current_instruction_index >= len(self.instruction_cache):
            self.is_running = False
            return
        binary_instr = self.instruction_cache[self.current_instruction_index]
        self.pc = format(self.current_instruction_index, '016b')
        self.execute_instruction(binary_instr)
        self.update_indicators()
        self.current_instruction_index += 1

        if not self.is_running:
            self.next_button.state(['disabled'])

    def update_indicators(self):
        if self.current_instruction_index < len(self.instruction_cache):
            current_instr = self.instruction_cache[self.current_instruction_index]
            opcode = current_instr[:4]
            operand = current_instr[4:]

            for var, addr in self.variable_map.items():
                operand = operand.replace('x' * len(var), format(addr, '012b'))

            self.pc_label.config(text=f"PC (Program Counter): {opcode}{operand}")
        else:
            self.pc_label.config(text=f"PC (Program Counter): End of Program")

        self.ac_label.config(text=f"AC (Accumulator): {self.ac}")
        self.sp_label.config(text=f"SP (Stack Pointer): {self.sp}")

    def assign_memory_addresses(self, program):
        addr = 0
        self.variable_map.clear()
        self.memory.clear()
        for line in program:
            parts = line.split()
            if len(parts) > 1 and not parts[1].isdigit():
                if parts[1] not in self.variable_map:
                    self.variable_map[parts[1]] = addr
                    addr += 1
            if parts[0] == 'SP':
                self.sp = format(addr, '016b')
                self.memory[addr] = self.sp
                addr += 1

        for var in self.variable_map:
            self.memory[self.variable_map[var]] = '0000000000000000'

    def populate_instruction_cache(self, program):
        self.instruction_cache.clear()
        self.labels.clear()
        self.instruction_cache_text.delete(1.0, tk.END)
        for line_num, line in enumerate(program):
            line = line.strip()
            if line.endswith(':'):
                label = line[:-1]
                self.labels[label] = line_num
            else:
                binary_instr = self.macro_to_binary(line)
                self.instruction_cache.append(binary_instr)
                self.instruction_cache_text.insert(tk.END, f"Instrução: {line_num + 1}: {binary_instr}\n")

        self.current_instruction_index = 0

    def macro_to_binary(self, macro_instruction):
        parts = macro_instruction.split()
        instr = parts[0]
        if instr in self.instructions:
            opcode = self.instructions[instr]
            if len(parts) > 1:
                if parts[1].isdigit():
                    operand = format(int(parts[1]), '012b')
                elif parts[1] in self.labels:
                    operand = format(self.labels[parts[1]], '012b')
                else:
                    operand = format(self.variable_map.get(parts[1], 0), '012b')
            else:
                operand = '000000000000'
            return opcode + operand
        return '0000000000000000'

    def execute_instruction(self, binary_instr):
        opcode = binary_instr[:4]
        operand = int(binary_instr[4:], 2)

        if opcode == '0000':  # LODD
            self.ac = self.get_memory_value(operand)
        elif opcode == '0001':  # STOD
            self.set_memory_value(operand, self.ac)
        elif opcode == '0010':  # ADDD
            self.ac = format((int(self.ac, 2) + int(self.get_memory_value(operand), 2)) & 0xFFFF, '016b')
        elif opcode == '0011':  # SUBD
            self.ac = format((int(self.ac, 2) - int(self.get_memory_value(operand), 2)) & 0xFFFF, '016b')
        elif opcode == '0100':  # JPOS
            if int(self.ac, 2) > 0:
                self.current_instruction_index = operand - 1
        elif opcode == '0101':  # JZER
            if int(self.ac, 2) == 0:
                self.current_instruction_index = operand - 1
        elif opcode == '1100':  # JNEG
            if int(self.ac, 2) & 0x8000:  #indicador de mais mais significativo complemento a dois
                self.current_instruction_index = operand - 1
                self.is_running = False
        elif opcode == '0110':
            self.current_instruction_index = operand - 1
            self.pc = format(operand, '016b')
        elif opcode == '0111':
            self.ac = format(operand, '016b')
        elif opcode == '1000':
            self.ac = self.get_memory_value(self.variable_map[operand])
        elif opcode == '1001':
            self.set_memory_value(self.variable_map[operand], self.ac)
        elif opcode == '1010':
            self.ac = format((int(self.ac, 2) + int(self.get_memory_value(self.variable_map[operand]), 2)) & 0xFFFF, '016b')
        elif opcode == '1011':
            self.push_to_stack(self.ac)
        elif opcode == '1101':
            self.ac = self.pop_from_stack()
        elif opcode == '1111':
            self.sp = format(operand, '016b')

        self.update_memory_display()
        self.update_cache_display()

    def get_memory_value(self, address):
        if address in self.data_cache:
            return self.data_cache[address]
        else:
            value = self.memory.get(address, '0000000000000000')
            self.data_cache[address] = value
            return value

    def set_memory_value(self, address, value):
        self.memory[address] = value
        self.data_cache[address] = value

    def push_to_stack(self, value):
        sp_value = int(self.sp, 2)
        self.set_memory_value(sp_value, value)
        self.sp = format(sp_value - 1, '016b')

    def pop_from_stack(self):
        sp_value = int(self.sp, 2) + 1
        value = self.get_memory_value(sp_value)
        self.sp = format(sp_value, '016b')
        return value

    def update_memory_display(self):
        self.memory_text.delete(1.0, tk.END)
        for addr in sorted(self.memory.keys()):
            self.memory_text.insert(tk.END, f"Address {addr}: {self.memory[addr]}\n")

    def update_cache_display(self):
        self.data_cache_text.delete(1.0, tk.END)
        for addr in sorted(self.data_cache.keys()):
            self.data_cache_text.insert(tk.END, f"Address {addr}: {self.data_cache[addr]}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = MIC1Simulator(root)
    root.mainloop()
