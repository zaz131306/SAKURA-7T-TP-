// hw/tb/tb_boot_rom.v — испытания secure boot ROM stub (§27.10):
// загрузка образа через $readmemh, валидность данных после сброса.
`timescale 1ns / 1ps
module tb_boot_rom;
    localparam ADDR_W = 4;   // 16 слов (stub)
    localparam DATA_W = 32;

    reg clk = 0;
    reg rst_n = 0;
    reg [ADDR_W-1:0] addr = 0;
    wire [DATA_W-1:0] data;
    wire valid;
    integer errors = 0;

    boot_rom #(.ADDR_W(ADDR_W), .DATA_W(DATA_W)) dut (
        .clk(clk), .rst_n(rst_n), .addr(addr), .data(data), .valid(valid)
    );

    always #5 clk = ~clk;
    task tick; begin @(posedge clk); #1; end endtask

    initial begin
        rst_n = 0; addr = 0;
        tick;
        if (valid !== 1'b0) begin errors = errors + 1; $display("V1: valid during reset"); end
        if (data !== 32'h0) begin errors = errors + 1; $display("V2: data not zeroed in reset"); end
        rst_n = 1;
        // addr=0 → первое слово образа (boot_rom.hex: DEADBEEF)
        tick;
        if (valid !== 1'b1) begin errors = errors + 1; $display("V3: valid not asserted"); end
        if (data !== 32'hDEADBEEF) begin errors = errors + 1; $display("D0: %h != DEADBEEF", data); end
        addr = 1; tick;
        if (data !== 32'hCAFEBABE) begin errors = errors + 1; $display("D1: %h != CAFEBABE", data); end
        addr = 2; tick;
        if (data !== 32'h5A5AA5A5) begin errors = errors + 1; $display("D2: %h != 5A5AA5A5", data); end
        addr = 3; tick;
        if (data !== 32'h0000000D) begin errors = errors + 1; $display("D3: %h != 0000000D", data); end

        if (errors == 0) $display("PASS: tb_boot_rom");
        else $display("FAIL: tb_boot_rom errors=%0d", errors);
        $finish;
    end
endmodule
