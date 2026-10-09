// hw/tb/tb_dma_ring.v — испытания DMA ring (§22.13):
// flow control (producer_ready при заполнении DEPTH), FIFO-порядок
// дескрипторов, одновременные push/pop.
`timescale 1ns / 1ps
module tb_dma_ring;
    localparam ADDR_W = 8;
    localparam LEN_W  = 4;
    localparam DEPTH  = 4;

    reg clk = 0;
    reg rst_n = 0;
    reg producer_valid = 0;
    reg [ADDR_W-1:0] producer_addr = 0;
    reg [LEN_W-1:0] producer_len = 0;
    wire producer_ready;
    wire consumer_valid;
    wire [ADDR_W-1:0] consumer_addr;
    wire [LEN_W-1:0] consumer_len;
    reg consumer_ready = 0;
    integer errors = 0;
    integer i;

    dma_ring #(.ADDR_W(ADDR_W), .LEN_W(LEN_W), .DEPTH(DEPTH)) dut (
        .clk(clk), .rst_n(rst_n),
        .producer_valid(producer_valid), .producer_addr(producer_addr),
        .producer_len(producer_len), .producer_ready(producer_ready),
        .consumer_valid(consumer_valid), .consumer_addr(consumer_addr),
        .consumer_len(consumer_len), .consumer_ready(consumer_ready)
    );

    always #5 clk = ~clk;
    task tick; begin @(posedge clk); #1; end endtask

    task push(input [ADDR_W-1:0] a, input [LEN_W-1:0] l); begin
        producer_addr = a; producer_len = l; producer_valid = 1;
        tick;
        producer_valid = 0;
    end endtask

    initial begin
        rst_n = 0; tick; rst_n = 1; tick;
        // пусто: producer_ready=1, consumer_valid=0
        if (producer_ready !== 1'b1) begin errors = errors + 1; $display("E1: not ready when empty"); end
        if (consumer_valid !== 1'b0) begin errors = errors + 1; $display("E2: valid when empty"); end

        // заполняем DEPTH дескрипторов
        for (i = 0; i < DEPTH; i = i + 1) push(i[ADDR_W-1:0] + 8'h10, i[LEN_W-1:0] + 1);
        tick;
        if (producer_ready !== 1'b0) begin errors = errors + 1; $display("F1: ready when full"); end
        if (consumer_valid !== 1'b1) begin errors = errors + 1; $display("F2: not valid when full"); end

        // попытка записи сверх DEPTH игнорируется (producer_ready=0)
        push(8'hFF, 4'hF);
        tick;

        // читаем в FIFO-порядке
        for (i = 0; i < DEPTH; i = i + 1) begin
            if (consumer_addr !== (i[ADDR_W-1:0] + 8'h10)) begin
                errors = errors + 1; $display("O%0d: addr %h != %h", i, consumer_addr, i[ADDR_W-1:0] + 8'h10);
            end
            if (consumer_len !== (i[LEN_W-1:0] + 1)) begin
                errors = errors + 1; $display("O%0d: len %h != %h", i, consumer_len, i[LEN_W-1:0] + 1);
            end
            consumer_ready = 1; tick; consumer_ready = 0; tick;
        end
        if (consumer_valid !== 1'b0) begin errors = errors + 1; $display("D1: valid after drain"); end
        if (producer_ready !== 1'b1) begin errors = errors + 1; $display("D2: not ready after drain"); end

        // одновременные push/pop
        push(8'hAA, 4'h5);
        producer_addr = 8'hBB; producer_len = 4'h6; producer_valid = 1;
        consumer_ready = 1;
        tick;
        producer_valid = 0; consumer_ready = 0;
        tick;
        if (consumer_addr !== 8'hBB || consumer_len !== 4'h6) begin
            errors = errors + 1; $display("P1: concurrent push/pop broken (%h/%h)", consumer_addr, consumer_len);
        end

        // сброс
        rst_n = 0; tick; rst_n = 1; tick;
        if (consumer_valid !== 1'b0) begin errors = errors + 1; $display("Z1: reset did not clear ring"); end

        if (errors == 0) $display("PASS: tb_dma_ring");
        else $display("FAIL: tb_dma_ring errors=%0d", errors);
        $finish;
    end
endmodule
