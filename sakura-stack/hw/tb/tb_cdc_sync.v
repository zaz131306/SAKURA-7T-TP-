// hw/tb/tb_cdc_sync.v — испытания CDC-синхронизатора (§22.10):
// цепочка из STAGES триггеров, ASYNC_REG, сброс в 0.
`timescale 1ns / 1ps
module tb_cdc_sync;
    localparam WIDTH = 4;
    localparam STAGES = 2;

    reg clk = 0;
    reg rst_n = 0;
    reg [WIDTH-1:0] async_in = 0;
    wire [WIDTH-1:0] sync_out;
    integer errors = 0;

    cdc_sync #(.WIDTH(WIDTH), .STAGES(STAGES)) dut (
        .dst_clk(clk), .dst_rst_n(rst_n),
        .async_in(async_in), .sync_out(sync_out)
    );

    always #5 clk = ~clk;   // 100 МГц модель

    task tick; begin @(posedge clk); #1; end endtask

    initial begin
        // сброс → 0
        rst_n = 0; async_in = 4'hA;
        tick; tick;
        rst_n = 1;
        tick;
        if (sync_out !== 4'h0) begin errors = errors + 1; $display("R1: not zeroed at reset (got %h)", sync_out); end

        // асинхронный вход появляется на выходе ровно после STAGES фронтов
        #2 async_in = 4'h5;           // изменение между фронтами (метастаб. окно)
        tick;
        if (sync_out === 4'h5) begin errors = errors + 1; $display("S1: propagated in <STAGES cycles"); end
        tick;
        if (sync_out !== 4'h5) begin errors = errors + 1; $display("S2: not propagated after STAGES=%0d (got %h)", STAGES, sync_out); end

        // следующая смена значения
        #3 async_in = 4'hC;
        tick;
        if (sync_out !== 4'h5) begin errors = errors + 1; $display("S3: early propagation"); end
        tick;
        if (sync_out !== 4'hC) begin errors = errors + 1; $display("S4: not propagated (got %h)", sync_out); end

        // повторный сброс (async_in обнулён — иначе цепочка повторно
        // синхронизирует прежнее значение, что корректно по смыслу CDC)
        async_in = 4'h0;
        rst_n = 0; tick; rst_n = 1; tick; tick;
        if (sync_out !== 4'h0) begin errors = errors + 1; $display("R2: reset did not clear chain (got %h)", sync_out); end

        if (errors == 0) $display("PASS: tb_cdc_sync");
        else $display("FAIL: tb_cdc_sync errors=%0d", errors);
        $finish;
    end
endmodule
