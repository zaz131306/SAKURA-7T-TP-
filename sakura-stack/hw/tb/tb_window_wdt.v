// hw/tb/tb_window_wdt.v — испытания window watchdog (§22.11, C-05):
// валидный kick в окне [MIN, MAX]; ранний kick → timeout; пропуск → sticky
// timeout; снятие только аппаратным сбросом.
`timescale 1ns / 1ps
module tb_window_wdt;
    // CLK_HZ=1000 → 1 цикл = 1 мс модели; MIN=2, MAX=5
    localparam CLK_HZ = 1000;
    localparam MIN_MS = 2;
    localparam MAX_MS = 5;

    reg clk = 0;
    reg rst_n = 0;
    reg kick = 0;
    wire timeout;
    integer errors = 0;

    window_wdt #(
        .CLK_HZ(CLK_HZ), .MIN_MS(MIN_MS), .MAX_MS(MAX_MS)
    ) dut (.clk(clk), .rst_n(rst_n), .kick(kick), .timeout(timeout));

    always #0.5 clk = ~clk;

    task tick; begin @(posedge clk); #0.1; end endtask

    task do_reset; begin
        rst_n = 0; kick = 0;
        tick; tick;
        rst_n = 1;
        tick;
    end endtask

    initial begin
        // --- A: валидные kick в окне — timeout не возникает ---
        do_reset;
        if (timeout !== 1'b0) begin errors = errors + 1; $display("A1: timeout after reset"); end
        // counter: 0→1 (edge1), 1→2 (edge2), 2→3 (edge3); kick на edge4 видит 3 ∈ [2,5)
        tick; tick; tick;
        kick = 1; tick; kick = 0;
        if (timeout !== 1'b0) begin errors = errors + 1; $display("A2: valid kick caused timeout"); end
        tick; tick; tick;
        kick = 1; tick; kick = 0;
        if (timeout !== 1'b0) begin errors = errors + 1; $display("A3: second valid kick caused timeout"); end

        // --- B: ранний kick (counter < MIN) → timeout ---
        do_reset;
        kick = 1; tick; kick = 0;   // kick видит counter=0 < MIN=2
        if (timeout !== 1'b1) begin errors = errors + 1; $display("B1: early kick not detected"); end
        // sticky: повторный валидный kick не снимает timeout
        tick; tick; tick;
        kick = 1; tick; kick = 0;
        if (timeout !== 1'b1) begin errors = errors + 1; $display("B2: timeout not sticky"); end

        // --- C: пропуск окна (counter >= MAX) → timeout, подсчёт остановлен ---
        do_reset;
        tick; tick; tick; tick; tick; tick; // counter достигает MAX=5
        if (timeout !== 1'b1) begin errors = errors + 1; $display("C1: missed window not detected"); end
        // sticky после просрочки
        kick = 1; tick; kick = 0; tick;
        if (timeout !== 1'b1) begin errors = errors + 1; $display("C2: timeout not sticky after expiry"); end

        // --- D: аппаратный сброс снимает timeout ---
        do_reset;
        if (timeout !== 1'b0) begin errors = errors + 1; $display("D1: reset did not clear timeout"); end

        if (errors == 0) $display("PASS: tb_window_wdt");
        else $display("FAIL: tb_window_wdt errors=%0d", errors);
        $finish;
    end
endmodule
