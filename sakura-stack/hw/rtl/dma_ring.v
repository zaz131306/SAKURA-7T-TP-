// fw/hdl/dma_ring.v — ТП SAKURA-7T-TP §22.13 (DMA descriptors ring)
// Требования: DMA bounds проверяются аппаратно; no access к secure memory;
// IOMMU для внешних мастер-портов (на уровне системы).
module dma_ring #(
    parameter ADDR_W = 40,
    parameter LEN_W  = 16,
    parameter DEPTH  = 64
) (
    input  wire               clk,
    input  wire               rst_n,
    input  wire               producer_valid,
    input  wire [ADDR_W-1:0]  producer_addr,
    input  wire [LEN_W-1:0]   producer_len,
    output wire               producer_ready,
    output wire               consumer_valid,
    output wire [ADDR_W-1:0]  consumer_addr,
    output wire [LEN_W-1:0]   consumer_len,
    input  wire               consumer_ready
);
    reg [ADDR_W+LEN_W-1:0] mem [0:DEPTH-1];
    reg [$clog2(DEPTH):0]   head, tail;

    assign producer_ready = ((head - tail) != DEPTH);
    assign consumer_valid = (head != tail);
    assign {consumer_addr, consumer_len} = mem[tail[$clog2(DEPTH)-1:0]];

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            head <= 0;
            tail <= 0;
        end else begin
            if (producer_valid && producer_ready) begin
                mem[head[$clog2(DEPTH)-1:0]] <= {producer_addr, producer_len};
                head <= head + 1;
            end
            if (consumer_valid && consumer_ready)
                tail <= tail + 1;
        end
    end
endmodule
