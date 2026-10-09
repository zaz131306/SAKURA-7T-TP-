// fw/hdl/cdc_sync.v — ТП SAKURA-7T-TP §22.10 (CDC synchronizer)
// Требования: цепочки >= 2 FF; ASYNC_REG; никаких комбинационных путей
// между доменами; reset synchronizers.
module cdc_sync #(
    parameter WIDTH = 1,
    parameter STAGES = 2
) (
    input  wire              dst_clk,
    input  wire              dst_rst_n,
    input  wire [WIDTH-1:0]  async_in,
    output wire [WIDTH-1:0]  sync_out
);
    (* ASYNC_REG = "TRUE" *)
    reg [WIDTH-1:0] sync_chain [0:STAGES-1];
    integer i;

    always @(posedge dst_clk or negedge dst_rst_n) begin
        if (!dst_rst_n) begin
            for (i = 0; i < STAGES; i = i + 1)
                sync_chain[i] <= {WIDTH{1'b0}};
        end else begin
            sync_chain[0] <= async_in;
            for (i = 1; i < STAGES; i = i + 1)
                sync_chain[i] <= sync_chain[i-1];
        end
    end

    assign sync_out = sync_chain[STAGES-1];
endmodule
